mod config;
mod socks5;

use std::net::SocketAddr;
use std::error::Error;
use tokio::net::{TcpSocket, TcpStream};
use config::{load_entire_file_content, ServerConfig, CONFIG_FILE_NAME};
use tokio_tls_helper::{ServerTlsConfig, Certificate, Identity};
use log::{error, warn, info};
use fdlimit::raise_fd_limit;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde_json::Value;
use socks5::{parse_handshake_body, parse_request_body};
use flexi_logger::{Duplicate, detailed_format};

fn init_log() {
    flexi_logger::Logger::with_str("debug")
        .duplicate_to_stdout(Duplicate::All)
        .format_for_stdout(detailed_format)
        .start()
        .unwrap_or_else(|e| panic!("logger initialization failed, err: {}", e));
}

fn reuse_socket(s: &TcpSocket) -> Result<(), Box<dyn Error>> {
    s.set_reuseaddr(true)?;
    Ok(())
}

async fn process_peer_stream(peer_stream: TcpStream, tls_config: ServerTlsConfig) {
    // accept tls connection
    let r = tls_config.tls_acceptor();
    if r.is_err() {
        error!("tls_acceptor build err: {}", r.unwrap_err());
        return;
    }
    let tls_acceptor = r.unwrap();

    let r = tls_acceptor.accept(peer_stream).await;
    if r.is_err() {
        error!("tls listener accept err: {}", r.unwrap_err());
        return;
    }
    let mut tls_peer_stream = r.unwrap();
    info!("accept tls connection of peer from {}", tls_peer_stream.get_ref().0.peer_addr().unwrap());

    let mut buffer = [0_u8; 1024];
    // read handshake data
    let r = tls_peer_stream.read(&mut buffer).await;
    if r.is_err() {
        error!("tls peer stream read err: {}", r.unwrap_err());
        return;
    }
    let v = (0..r.unwrap()).map(|x: usize| buffer[x]).collect();
    let r = parse_handshake_body(&v);
    if r.is_err() {
        error!("parse handshake body err: {}", r.unwrap_err());
        return;
    }

    let r = tls_peer_stream.write(&mut [0x05_u8, 0x00_u8]).await;
    if r.is_err() {
        error!("tls peer stream write err: {}", r.unwrap_err());
        return;
    }

    // read request data
    let r = tls_peer_stream.read(&mut buffer).await;
    if r.is_err() {
        error!("tls peer stream read err: {}", r.unwrap_err());
        return;
    }
    let v = (0..r.unwrap()).map(|x: usize| buffer[x]).collect();
    let r = parse_request_body(&v);
    if r.is_err() {
        error!("parse request body err: {}", r.unwrap_err());
        return;
    }
    let (cmd, atype, host, port) = r.unwrap();

    if cmd != Value::from(0x01_u8) {
        warn!("cmd 0x{:x} not support", cmd);
        return;
    }
    if atype != Value::from(0x04_u8) {
        warn!("ip v6 not support");
        return;
    }
    info!("proxy to: {}:{}", host.clone(), port);

    let addr_conn: SocketAddr =
        format!("{}:{}", host.clone(), port)
            .parse()
            .unwrap_or_else(|e| { panic!("parse proxy to addr err: {}", e) });

    // new socket and set reuse
    let socket_connect = TcpSocket::new_v4().unwrap();
    reuse_socket(&socket_connect)
        .unwrap_or_else(|e| { panic!("set connect socket reuse option err: {}", e) });

    let connect_timeout = tokio::time::Duration::from_secs(5);
    let r = tokio::time::timeout(
        connect_timeout,
        socket_connect.connect(addr_conn),
    ).await;
    if r.is_err() {
        error!("tcp stream connect err: {}", r.unwrap_err());
        return;
    }
    let r = r.unwrap();
    if r.is_err() {
        error!("tcp stream connect err: {}", r.unwrap_err());
        return;
    }
    let tcp_proxy_stream = r.unwrap();

    info!("client: tcp proxy conn established");

    let r = tls_peer_stream.write(
        &mut [0x05_u8, 0x00_u8, 0x00_u8, 0x01_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8, 0x00_u8])
        .await;
    if r.is_err() {
        error!("tls peer stream write err: {}", r.unwrap_err());
        return;
    }

    let (mut proxy_stream_reader, mut proxy_stream_writer) = tcp_proxy_stream.into_split();
    let (mut tls_stream_reader, mut tls_stream_writer) = tokio::io::split(tls_peer_stream);

    let fut1 = tokio::spawn(async move {
        let r = tokio::io::copy(&mut tls_stream_reader, &mut proxy_stream_writer).await;
        if r.is_err() {
            error!("copy [tls->proxy] err: {}", r.unwrap_err());
        }
    });

    let fut2 = tokio::spawn(async move {
        let r = tokio::io::copy(&mut proxy_stream_reader, &mut tls_stream_writer).await;
        if r.is_err() {
            error!("copy [proxy->tls] err: {}", r.unwrap_err());
        }
    });

    let (_, _) = tokio::join!(fut1, fut2);
}

#[tokio::main]
async fn main() {
    init_log();

    // raise fd limit to max
    let r = raise_fd_limit();
    if r.is_none() {
        info!("not support to raise system fd limit");
    } else {
        info!("raise system fd limit to {}", r.unwrap());
    }

    let json_str = load_entire_file_content(CONFIG_FILE_NAME);
    let config = ServerConfig::from_json_str(&json_str);

    let ca_cert_str = load_entire_file_content(config.ca_cert.as_str());
    let ca_cert = Certificate::from_pem(ca_cert_str.as_bytes());

    let key_str = load_entire_file_content(config.server_key.as_str());
    let cert_str = load_entire_file_content(config.server_cert.as_str());
    let server_identity = Identity::from_pem(cert_str.as_str(), key_str.as_str());

    let tls_config = ServerTlsConfig::new()
        .client_ca_root(ca_cert)
        .identity(server_identity);

    let addr_listen: SocketAddr =
        format!("{}:{}", config.listen_host, config.listen_port)
            .parse()
            .unwrap_or_else(|e| { panic!("parse listen addr err: {}", e) });

    // new socket and set reuse
    let socket_listen = TcpSocket::new_v4().unwrap();
    reuse_socket(&socket_listen)
        .unwrap_or_else(|e| { panic!("set listen socket reuse option err: {}", e) });

    // bind
    socket_listen.bind(addr_listen)
        .unwrap_or_else(|e| { panic!("bind listen addr to socket err: {}", e) });

    // start to listen
    let tcp_listener = socket_listen
        .listen(1024)
        .unwrap_or_else(|e| { panic!("socket start listening err: {}", e) });

    loop {
        let r = tcp_listener.accept().await;
        if r.is_err() {
            error!("tcp listener accept err: {}", r.unwrap_err());
            continue;
        }
        let (peer_stream, _) = r.unwrap();

        let tls_config_clone = tls_config.clone();
        tokio::spawn(async move {
            process_peer_stream(peer_stream, tls_config_clone).await;
        });
    }
}
