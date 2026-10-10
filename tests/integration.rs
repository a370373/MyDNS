use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

#[path = "../src/dns/query.rs"]
#[allow(dead_code)]
mod query;

const DNS_PORT: u16 = 15353;

static SERVER_LOCK: Mutex<()> = Mutex::new(());

struct Server {
    child: Child,
    _guard: MutexGuard<'static, ()>,
}

impl Server {
    fn start() -> Self {
        let guard = SERVER_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Run in a scratch dir so generated certs stay out of the repo.
        let dir = std::env::temp_dir()
            .join(format!("mydns-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_MyDNS"))
            .arg("--mode=termux")
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn MyDNS");

        let server = Server { child, _guard: guard };

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if udp_query(&packet("ready.test", 15, 1, 0x0100), 500)
                .is_some()
            {
                return server;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("MyDNS did not start listening");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn packet(name: &str, qtype: u16, id: u16, flags: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&flags.to_be_bytes());
    p.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p
}

fn udp_query(request: &[u8], timeout_ms: u64) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .unwrap();
    socket
        .send_to(request, ("127.0.0.1", DNS_PORT))
        .ok()?;
    let mut buffer = [0u8; 4096];
    let (size, _) = socket.recv_from(&mut buffer).ok()?;
    Some(buffer[..size].to_vec())
}

fn rcode(response: &[u8]) -> u8 {
    response[3] & 0x0f
}

fn answer_types(response: &[u8]) -> Vec<u16> {
    let questions = u16::from_be_bytes([response[4], response[5]]);
    let answers = u16::from_be_bytes([response[6], response[7]]);
    let mut pos = 12;

    let skip_name = |pos: &mut usize| loop {
        let byte = response[*pos];
        if byte & 0xc0 == 0xc0 {
            *pos += 2;
            return;
        }
        if byte == 0 {
            *pos += 1;
            return;
        }
        *pos += byte as usize + 1;
    };

    for _ in 0..questions {
        skip_name(&mut pos);
        pos += 4;
    }

    let mut types = Vec::new();
    for _ in 0..answers {
        skip_name(&mut pos);
        types.push(u16::from_be_bytes([response[pos], response[pos + 1]]));
        let rdlength =
            u16::from_be_bytes([response[pos + 8], response[pos + 9]]);
        pos += 10 + rdlength as usize;
    }
    types
}

fn assert_alive() {
    let reply = udp_query(&packet("alive.test", 15, 0x7777, 0x0100), 3000)
        .expect("server stopped answering UDP");
    assert_eq!(rcode(&reply), 4);
}

#[test]
fn unsupported_type_gets_notimp_and_echoes_id() {
    let _server = Server::start();
    let reply = udp_query(&packet("example.com", 15, 0xBEEF, 0x0100), 3000)
        .unwrap();
    assert_eq!(&reply[..2], &0xBEEFu16.to_be_bytes());
    assert_eq!(rcode(&reply), 4);
}

#[test]
fn malformed_udp_packets_do_not_kill_the_server() {
    let _server = Server::start();

    let header = |qd: u16| {
        let mut h = vec![0, 1, 1, 0];
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&[0; 6]);
        h
    };

    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0; 11],
        header(1),
        header(0),
        header(65535),
        [header(1), vec![0x3f, b'a', b'b', b'c']].concat(),
        [header(1), vec![0xc0, 0x0c, 0, 1, 0, 1]].concat(),
        [header(1), vec![0xc0, 0xff, 0, 1, 0, 1]].concat(),
        [header(1), vec![64], vec![b'a'; 64], vec![0, 0, 1, 0, 1]].concat(),
        vec![0x41; 4000],
        (0..512).map(|i| (i * 31 % 251) as u8).collect(),
    ];
    cases.push([header(1), vec![0, 0, 1]].concat());

    for case in cases {
        let _ = udp_query(&case, 300);
        assert_alive();
    }
}

#[test]
fn responses_are_dropped_and_other_opcodes_refused() {
    let _server = Server::start();

    let as_response = packet("example.com", 15, 1, 0x8100);
    assert!(udp_query(&as_response, 500).is_none());

    let status_opcode = packet("example.com", 15, 2, 0x1100);
    let reply = udp_query(&status_opcode, 3000).unwrap();
    assert_eq!(rcode(&reply), 4);
    assert_alive();
}

#[test]
fn udp_survives_clients_that_vanish_before_the_reply() {
    let _server = Server::start();

    for i in 0..300u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let _ = socket.send_to(
            &packet("example.com", 15, i, 0x0100),
            ("127.0.0.1", DNS_PORT),
        );
        drop(socket);
    }

    thread::sleep(Duration::from_millis(300));
    assert_alive();
}

fn tcp_roundtrip(stream: &mut TcpStream, request: &[u8]) -> Vec<u8> {
    let mut framed = (request.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(request);
    stream.write_all(&framed).unwrap();

    let mut length = [0u8; 2];
    stream.read_exact(&mut length).unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).unwrap();
    body
}

#[test]
fn tcp_connection_is_reusable_and_idle_connections_are_closed() {
    let _server = Server::start();

    let mut stream =
        TcpStream::connect(("127.0.0.1", DNS_PORT)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();

    let first = tcp_roundtrip(&mut stream, &packet("a.test", 15, 1, 0x0100));
    assert_eq!(rcode(&first), 4);

    // A broken query must be answered, not reset, and the connection
    // must keep working afterwards.
    let broken = [vec![0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0], vec![0x3f, b'a']]
        .concat();
    let second = tcp_roundtrip(&mut stream, &broken);
    assert_eq!(rcode(&second), 1);

    let third = tcp_roundtrip(&mut stream, &packet("b.test", 15, 3, 0x0100));
    assert_eq!(&third[..2], &3u16.to_be_bytes());

    let started = Instant::now();
    let mut byte = [0u8; 1];
    let read = stream.read(&mut byte).unwrap_or(0);
    assert_eq!(read, 0, "server should close an idle connection");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "idle connection was held open for {:?}",
        started.elapsed()
    );
}

// ---- upstream exchange: spoofed / stray replies must be ignored ----

fn fake_reply(query: &[u8], id: u16, flags_hi: u8, marker: u8) -> Vec<u8> {
    let mut r = query.to_vec();
    r[..2].copy_from_slice(&id.to_be_bytes());
    r[2] = flags_hi;
    r.push(marker);
    r
}

fn run_fake_server(
    script: impl FnOnce(&UdpSocket, SocketAddr, Vec<u8>) + Send + 'static,
) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buffer = [0u8; 512];
        let (size, client) = socket.recv_from(&mut buffer).unwrap();
        script(&socket, client, buffer[..size].to_vec());
    });
    addr
}

#[test]
fn exchange_ignores_wrong_id_and_non_response_replies() {
    let (id, q) = query::build_query("example.com", query::TYPE_A);
    let server = run_fake_server(move |socket, client, query| {
        socket.send_to(&fake_reply(&query, id ^ 1, 0x80, 1), client).unwrap();
        socket.send_to(&fake_reply(&query, id, 0x00, 2), client).unwrap();
        socket.send_to(&fake_reply(&query, id, 0x80, 3), client).unwrap();
    });

    let reply =
        query::exchange_with(server, &q, id, Duration::from_secs(2))
            .unwrap();
    assert_eq!(*reply.last().unwrap(), 3);
}

#[test]
fn exchange_ignores_replies_from_other_sockets() {
    let (id, q) = query::build_query("example.com", query::TYPE_A);
    let server = run_fake_server(move |socket, client, query| {
        let spoofer = UdpSocket::bind("127.0.0.1:0").unwrap();
        spoofer.send_to(&fake_reply(&query, id, 0x80, 9), client).unwrap();
        thread::sleep(Duration::from_millis(100));
        socket.send_to(&fake_reply(&query, id, 0x80, 4), client).unwrap();
    });

    let reply =
        query::exchange_with(server, &q, id, Duration::from_secs(2))
            .unwrap();
    assert_eq!(*reply.last().unwrap(), 4);
}

#[test]
fn exchange_times_out_when_nobody_answers() {
    let (id, q) = query::build_query("example.com", query::TYPE_A);
    let server = run_fake_server(|_, _, _| {
        thread::sleep(Duration::from_secs(3));
    });

    let started = Instant::now();
    let error =
        query::exchange_with(server, &q, id, Duration::from_millis(400))
            .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn upstream_transaction_ids_are_not_sequential() {
    let ids: std::collections::HashSet<u16> = (0..64)
        .map(|_| query::build_query("example.com", query::TYPE_A).0)
        .collect();
    assert!(ids.len() > 40, "only {} distinct ids", ids.len());
}

// ---- need real internet access: cargo test -- --ignored ----

#[test]
#[ignore]
fn network_cname_chain_is_answered_and_cached() {
    let _server = Server::start();

    for round in 0..2 {
        let reply = udp_query(
            &packet("www.github.com", 1, 0x1234, 0x0100),
            15000,
        )
        .expect("no reply");
        assert_eq!(rcode(&reply), 0, "round {round}");
        let types = answer_types(&reply);
        assert!(types.contains(&5), "CNAME missing: {types:?}");
        assert!(types.contains(&1), "A missing: {types:?}");
    }
}

#[test]
#[ignore]
fn network_deeply_delegated_zone_is_resolved() {
    let _server = Server::start();
    let reply = udp_query(&packet("www.baidu.com", 1, 0x2222, 0x0100), 30000)
        .expect("no reply");
    assert!(answer_types(&reply).contains(&1));
}

#[test]
#[ignore]
fn network_cname_into_glueless_delegation_is_resolved() {
    // itunes.apple.com -> ...v.aaplimg.com, whose delegation carries NS names without glue.
    let _server = Server::start();

    for (id, name) in [
        (0x2301, "itunes.apple.com"),
        (0x2302, "updates.cdn-apple.com"),
        (0x2303, "gsp-ssl.ls.apple.com"),
    ] {
        let reply = udp_query(&packet(name, 1, id, 0x0100), 30000)
            .expect("no reply");
        assert!(
            answer_types(&reply).contains(&1),
            "{} returned no A record",
            name
        );
    }
}

#[test]
#[ignore]
fn network_concurrent_lookups_are_not_serialized() {
    let _server = Server::start();
    let names = [
        "www.google.com", "www.github.com", "www.cloudflare.com",
        "www.microsoft.com", "www.apple.com", "www.amazon.com",
        "www.netflix.com", "www.reddit.com", "www.mozilla.org",
        "www.python.org", "www.rust-lang.org", "www.debian.org",
    ];

    let started = Instant::now();
    let handles: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let request = packet(name, 1, i as u16, 0x0100);
            thread::spawn(move || udp_query(&request, 30000).is_some())
        })
        .collect();

    let answered =
        handles.into_iter().filter(|_| true).map(|h| h.join().unwrap());
    assert!(answered.filter(|ok| *ok).count() == names.len());
    assert!(started.elapsed() < Duration::from_secs(20));
}
