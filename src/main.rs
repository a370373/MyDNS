mod dns {
    pub mod packet;
    pub mod query;
    pub mod record;
}

mod resolver {
    pub mod cache;
    pub mod recursive;
    pub mod root;
    pub mod service;
}

mod server {
    pub mod doh;
    pub mod tcp;
    pub mod udp;
}


#[tokio::main]
async fn main() {
    println!("MyDNS Server");

    let mode =
        std::env::args()
            .skip(1)
            .find_map(|arg| {
                arg.strip_prefix("--mode=")
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| {
                "native".to_string()
            });

    let (dns_address, doh_address) =
        match mode.as_str() {
            "termux" => (
                "127.0.0.1:15353",
                "127.0.0.1:18443",
            ),

            "native" => (
                "127.0.0.1:53",
                "127.0.0.1:443",
            ),

            _ => {
                eprintln!(
                    "Unknown mode: {}",
                    mode
                );

                eprintln!(
                    "Usage: MyDNS [--mode=termux|native]"
                );

                return;
            }
        };

    println!(
        "Mode: {}",
        mode
    );

    println!(
        "DNS: {}",
        dns_address
    );

    println!(
        "DoH: https://{}/dns-query",
        doh_address
    );


    /*
     * One shared Resolver + Cache.
     *
     * UDP, TCP and DoH all use this
     * same service instance.
     */
    let service =
        resolver::service::DnsService::new();


    /*
     * UDP DNS
     */
    let udp_address =
        dns_address.to_string();

    let udp_service =
        service.clone();

    std::thread::spawn(move || {
        if let Err(error) =
            server::udp::run(
                &udp_address,
                udp_service,
            )
        {
            eprintln!(
                "MyDNS UDP server error: {}",
                error
            );
        }
    });


    /*
     * TCP DNS
     */
    let tcp_address =
        dns_address.to_string();

    let tcp_service =
        service.clone();

    std::thread::spawn(move || {
        if let Err(error) =
            server::tcp::run(
                &tcp_address,
                tcp_service,
            )
        {
            eprintln!(
                "MyDNS TCP server error: {}",
                error
            );
        }
    });


    /*
     * DoH
     */
    let cert_path =
        "certs/mydns-cert.pem";

    let key_path =
        "certs/mydns-key.pem";

    if let Err(error) =
        server::doh::run(
            doh_address,
            cert_path,
            key_path,
            service,
        )
        .await
    {
        eprintln!(
            "MyDNS DoH server error: {}",
            error
        );
    }
}
