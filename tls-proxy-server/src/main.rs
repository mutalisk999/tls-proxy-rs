mod config;
mod socks5;

use std::net::SocketAddr;
use std::error::Error;
use tokio::net::{TcpSocket, TcpStream};
use config::{load_entire_file_content, ServerConfig, CONFIG_FILE_NAME};
use tokio_tls_helper::{ServerTlsConfig, Certificate, Identity};
use log::{error, info};
use fdlimit::raise_fd_limit;

fn reuse_socket(s: &TcpSocket) -> Result<(), Box<dyn Error>> {
    s.set_reuseaddr(true)?;
    Ok(())
}

#[tokio::main]
async fn main() {
    // raise fd limit to max
    let r = raise_fd_limit();
    if r.is_none() {
        info!("not support to raise system fd limit");
    }
    info!("raise system fd limit to {}", r.unwrap());

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

    let tls_acceptor = tls_config
        .tls_acceptor()
        .unwrap_or_else(|e| { panic!("tls_acceptor build err: {}", e) });

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
        let (peer_stream, peer_addr) = r.unwrap();

        let r = tls_acceptor.accept(peer_stream).await;
        if r.is_err() {
            error!("tls listener accept err: {}", r.unwrap_err());
            continue;
        }
        let tls_peer_stream = r.unwrap();
        info!("accept tls connection of peer from {}", peer_addr);
    }
}
