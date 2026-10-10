use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::dns::packet::build_error_response;
use crate::resolver::service::DnsService;

const MAX_CONNECTIONS: usize = 256;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

struct ActiveConnection(Arc<AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn run(
    address: &str,
    service: DnsService,
) -> io::Result<()> {
    let listener =
        TcpListener::bind(address)?;

    println!(
        "MyDNS TCP listening on {}",
        address
    );

    let active = Arc::new(AtomicUsize::new(0));

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if active.fetch_add(1, Ordering::SeqCst)
                    >= MAX_CONNECTIONS
                {
                    active.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }

                let service =
                    service.clone();

                let guard = ActiveConnection(
                    Arc::clone(&active),
                );

                thread::spawn(move || {
                    let _guard = guard;

                    if let Err(error) =
                        handle_connection(
                            stream,
                            service,
                        )
                    {
                        eprintln!(
                            "MyDNS TCP connection error: {}",
                            error
                        );
                    }
                });
            }

            Err(error) => {
                eprintln!(
                    "MyDNS TCP accept error: {}",
                    error
                );
            }
        }
    }

    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    service: DnsService,
) -> io::Result<()> {
    // An idle or stalled client must not pin a thread forever.
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_nodelay(true)?;

    loop {
        /*
         * DNS over TCP:
         *
         * 2-byte big-endian length
         * followed by DNS message.
         */
        let mut length_bytes =
            [0u8; 2];

        match stream.read_exact(
            &mut length_bytes,
        ) {
            Ok(()) => {}

            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(());
            }

            Err(error) => {
                return Err(error);
            }
        }

        let length =
            u16::from_be_bytes(
                length_bytes,
            ) as usize;

        if length == 0 {
            return Ok(());
        }

        let mut request =
            vec![0u8; length];

        stream.read_exact(
            &mut request,
        )?;

        let response =
            match service.handle_query(&request) {
                Ok(response) => response,

                // Answer SERVFAIL instead of resetting the connection.
                Err(_) => build_error_response(&request, 2)?,
            };

        let response_length =
            u16::try_from(
                response.len(),
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS response too large",
                )
            })?;

        let mut framed =
            Vec::with_capacity(response.len() + 2);

        framed.extend_from_slice(
            &response_length.to_be_bytes(),
        );
        framed.extend_from_slice(&response);

        stream.write_all(&framed)?;
        stream.flush()?;
    }
}
