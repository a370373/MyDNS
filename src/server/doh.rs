use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{
        header,
        HeaderValue,
        StatusCode,
    },
    response::Response,
    routing::{get, post},
    Router,
};

use axum_server::tls_rustls::RustlsConfig;

use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine,
};

use rcgen::{
    BasicConstraints,
    CertificateParams,
    DnType,
    ExtendedKeyUsagePurpose,
    IsCa,
    Issuer,
    KeyPair,
    KeyUsagePurpose,
};

use serde::Deserialize;

use std::{
    error::Error,
    fs,
    net::SocketAddr,
    path::Path,
};

use crate::resolver::service::DnsService;


#[derive(Debug, Deserialize)]
pub struct DohQuery {
    dns: String,
}


#[derive(Clone)]
struct DohState {
    service: DnsService,
}


fn dns_response(
    packet: Vec<u8>,
) -> Response {
    let mut response =
        Response::new(packet.into());

    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(
            "application/dns-message",
        ),
    );

    response
}


async fn post_dns(
    State(state): State<DohState>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let packet =
        body.to_vec();

    if packet.is_empty() {
        return Err(
            StatusCode::BAD_REQUEST
        );
    }

    let response =
        state
            .service
            .handle_query(&packet)
            .map_err(|_| {
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    Ok(dns_response(response))
}


async fn get_dns(
    State(state): State<DohState>,
    Query(query): Query<DohQuery>,
) -> Result<Response, StatusCode> {
    let packet =
        URL_SAFE_NO_PAD
            .decode(
                query.dns.as_bytes()
            )
            .map_err(|_| {
                StatusCode::BAD_REQUEST
            })?;

    if packet.is_empty() {
        return Err(
            StatusCode::BAD_REQUEST
        );
    }

    let response =
        state
            .service
            .handle_query(&packet)
            .map_err(|_| {
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    Ok(dns_response(response))
}


fn ensure_certificate(
    cert_path: &str,
    key_path: &str,
) -> Result<(), Box<dyn Error>> {
    let ca_path =
        "certs/mydns-ca.pem";

    let ca_key_path =
        "certs/mydns-ca-key.pem";

    fs::create_dir_all(
        "certs"
    )?;

    if Path::new(cert_path).exists()
        && Path::new(key_path).exists()
        && Path::new(ca_path).exists()
        && Path::new(ca_key_path).exists()
    {
        return Ok(());
    }

    /*
     * MyDNS Local CA
     */
    let mut ca_params =
        CertificateParams::new(
            Vec::<String>::new()
        )?;

    ca_params.is_ca =
        IsCa::Ca(
            BasicConstraints::Unconstrained
        );

    ca_params
        .distinguished_name
        .push(
            DnType::CommonName,
            "MyDNS Local CA",
        );

    ca_params
        .key_usages
        .push(
            KeyUsagePurpose::DigitalSignature
        );

    ca_params
        .key_usages
        .push(
            KeyUsagePurpose::KeyCertSign
        );

    ca_params
        .key_usages
        .push(
            KeyUsagePurpose::CrlSign
        );

    let ca_key =
        KeyPair::generate()?;

    let ca_cert =
        ca_params.self_signed(
            &ca_key
        )?;

    fs::write(
        ca_path,
        ca_cert.pem().as_bytes(),
    )?;

    fs::write(
        ca_key_path,
        ca_key.serialize_pem()
            .as_bytes(),
    )?;

    /*
     * MyDNS HTTPS certificate
     */
    let mut server_params =
        CertificateParams::new(
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ]
        )?;

    server_params
        .distinguished_name
        .push(
            DnType::CommonName,
            "MyDNS",
        );

    server_params
        .key_usages
        .push(
            KeyUsagePurpose::DigitalSignature
        );

    server_params
        .extended_key_usages
        .push(
            ExtendedKeyUsagePurpose::ServerAuth
        );

    server_params
        .use_authority_key_identifier_extension =
        true;

    let server_key =
        KeyPair::generate()?;

    let issuer =
        Issuer::new(
            ca_params,
            ca_key,
        );

    let server_cert =
        server_params.signed_by(
            &server_key,
            &issuer,
        )?;

    let certificate_chain =
        format!(
            "{}{}",
            server_cert.pem(),
            ca_cert.pem()
        );

    fs::write(
        cert_path,
        certificate_chain.as_bytes(),
    )?;

    fs::write(
        key_path,
        server_key
            .serialize_pem()
            .as_bytes(),
    )?;

    println!(
        "Generated MyDNS Local CA: {}",
        ca_path
    );

    println!(
        "Generated MyDNS DoH certificate: {}",
        cert_path
    );

    println!(
        "Install this CA on Android to trust MyDNS HTTPS:"
    );

    println!(
        "  {}",
        ca_path
    );

    Ok(())
}


pub async fn run(
    address: &str,
    cert_path: &str,
    key_path: &str,
    service: DnsService,
) -> Result<(), Box<dyn Error>> {
    ensure_certificate(
        cert_path,
        key_path,
    )?;

    let state =
        DohState {
            service,
        };

    let app =
        Router::new()
            .route(
                "/dns-query",
                get(get_dns)
                    .post(post_dns),
            )
            .with_state(state);

    let config =
        RustlsConfig::from_pem_file(
            cert_path,
            key_path,
        )
        .await?;

    let address: SocketAddr =
        address.parse()?;

    println!(
        "MyDNS DoH listening on https://{}/dns-query",
        address
    );

    axum_server::bind_rustls(
        address,
        config,
    )
    .serve(
        app.into_make_service()
    )
    .await?;

    Ok(())
}
