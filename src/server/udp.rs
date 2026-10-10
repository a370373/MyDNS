use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::resolver::service::DnsService;

const MAX_IN_FLIGHT: usize = 256;

struct InFlight(Arc<AtomicUsize>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn run(
    address: &str,
    service: DnsService,
) -> io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(address)?);

    println!(
        "MyDNS UDP listening on {}",
        address
    );

    let in_flight = Arc::new(AtomicUsize::new(0));
    let mut buffer = vec![0u8; 65535];

    loop {
        let (size, client) =
            match socket.recv_from(&mut buffer) {
                Ok(received) => received,

                // On Windows a client that vanished makes the next
                // recv_from fail with ConnectionReset; that must not
                // stop the server.
                Err(error) => {
                    if error.kind()
                        != io::ErrorKind::ConnectionReset
                    {
                        eprintln!(
                            "MyDNS UDP receive error: {}",
                            error
                        );

                        thread::sleep(
                            Duration::from_millis(50),
                        );
                    }

                    continue;
                }
            };

        if size < 12 {
            continue;
        }

        if in_flight.fetch_add(1, Ordering::SeqCst)
            >= MAX_IN_FLIGHT
        {
            in_flight.fetch_sub(1, Ordering::SeqCst);
            continue;
        }

        let guard = InFlight(Arc::clone(&in_flight));
        let request = buffer[..size].to_vec();
        let socket = Arc::clone(&socket);
        let service = service.clone();

        thread::spawn(move || {
            let _guard = guard;

            match service.handle_query(&request) {
                Ok(response) => {
                    if let Err(error) =
                        socket.send_to(&response, client)
                    {
                        eprintln!(
                            "MyDNS UDP send error: {}",
                            error
                        );
                    }
                }

                Err(error) => {
                    eprintln!(
                        "MyDNS UDP query error: {}",
                        error
                    );
                }
            }
        });
    }
}
