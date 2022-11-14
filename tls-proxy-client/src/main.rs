mod config;

use std::net::SocketAddr;
use tokio;
use tokio::net::{TcpSocket, TcpStream};
use std::error::Error;
use config::{load_entire_file_content, ClientConfig, CONFIG_FILE_NAME};
use tokio_tls_helper::{ClientTlsConfig, Certificate, Identity};
use http::Uri;
use log::{error, info};
use fdlimit::raise_fd_limit;

fn reuse_socket(s: &TcpSocket) -> Result<(), Box<dyn Error>> {
    s.set_reuseaddr(true)?;
    Ok(())
}

async fn process_peer_stream(peer_stream: TcpStream, config: ClientConfig,
                             tls_config: ClientTlsConfig) {
    let tls_connector = tls_config
        .tls_connector(Uri::from_static("localhost"))
        .unwrap_or_else(|e| { panic!("tls_connector build err: {}", e) });

    let addr_conn: SocketAddr =
        format!("{}:{}", config.server_host, config.server_port)
            .parse()
            .unwrap_or_else(|e| { panic!("parse server addr err: {}", e) });

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
    let tcp_stream = r.unwrap();

    let r = tls_connector.connect(tcp_stream).await;
    if r.is_err() {
        error!("tls stream connect err: {}", r.unwrap_err());
        return;
    }
    let tls_stream = r.unwrap();

    info!("client: tls conn established");

    let (mut peer_stream_reader, mut peer_stream_writer) = peer_stream.into_split();
    let (mut tls_stream_reader, mut tls_stream_writer) = tokio::io::split(tls_stream);

    let fut1 = tokio::spawn(async move {
        let r = tokio::io::copy(&mut peer_stream_reader, &mut tls_stream_writer).await;
        if r.is_err() {
            error!("copy [peer->tls] err: {}", r.unwrap_err());
        }
    });

    let fut2 = tokio::spawn(async move {
        let r = tokio::io::copy(&mut tls_stream_reader, &mut peer_stream_writer).await;
        if r.is_err() {
            error!("copy [tls->peer] err: {}", r.unwrap_err());
        }
    });

    let (_, _) = tokio::join!(fut1, fut2);
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
    let config = ClientConfig::from_json_str(&json_str);

    let ca_cert_str = load_entire_file_content(config.ca_cert.as_str());
    let ca_cert = Certificate::from_pem(ca_cert_str.as_bytes());

    let key_str = load_entire_file_content(config.client_key.as_str());
    let cert_str = load_entire_file_content(config.client_cert.as_str());
    let client_identity = Identity::from_pem(cert_str.as_str(), key_str.as_str());

    let tls_config = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(client_identity);

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
    let listener = socket_listen
        .listen(1024)
        .unwrap_or_else(|e| { panic!("socket start listening err: {}", e) });

    loop {
        let r = listener.accept().await;
        if r.is_err() {
            error!("listener accept err: {}", r.unwrap_err());
            continue;
        }
        let (peer_stream, peer_addr) = r.unwrap();
        info!("connection of peer from {}", peer_addr);

        let config_clone = config.clone();
        let tls_config_clone = tls_config.clone();
        tokio::spawn(async move {
            process_peer_stream(peer_stream, config_clone, tls_config_clone).await;
        });
    }
}
