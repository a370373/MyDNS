use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use crate::resolver::service::DnsService;

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

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let service =
                    service.clone();

                thread::spawn(move || {
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
                if error.kind()
                    == io::ErrorKind::UnexpectedEof =>
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
            continue;
        }

        let mut request =
            vec![0u8; length];

        stream.read_exact(
            &mut request,
        )?;

        let response =
            service.handle_query(
                &request,
            )?;

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

        stream.write_all(
            &response_length
                .to_be_bytes(),
        )?;

        stream.write_all(
            &response,
        )?;

        stream.flush()?;
    }
}
