use std::io;
use std::net::UdpSocket;

use crate::resolver::service::DnsService;

pub fn run(
    address: &str,
    service: DnsService,
) -> io::Result<()> {
    let socket = UdpSocket::bind(address)?;

    println!(
        "MyDNS UDP listening on {}",
        address
    );

    loop {
        let mut request = [0u8; 65535];

        let (size, client) =
            socket.recv_from(&mut request)?;

        let request =
            &request[..size];

        if request.len() < 12 {
            continue;
        }

        let response =
            match service.handle_query(request) {
                Ok(response) => response,

                Err(error) => {
                    eprintln!(
                        "MyDNS UDP query error: {}",
                        error
                    );

                    continue;
                }
            };

        socket.send_to(
            &response,
            client,
        )?;
    }
}
