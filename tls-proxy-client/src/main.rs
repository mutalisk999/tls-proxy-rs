mod config;

use std::net::SocketAddr;
use tokio;
use tokio::net::{TcpSocket, TcpStream};
use std::error::Error;
use config::{load_entire_file_content, ClientConfig};
use tokio_tls_helper::{ClientTlsConfig, Certificate, Identity};
use http::Uri;
use log::{error, info};

use crate::config::CONFIG_FILE_NAME;

fn reuse_socket(s: &TcpSocket) -> Result<(), Box<dyn Error>> {
    s.set_reuseaddr(true)?;
    Ok(())
}

async fn process_peer_stream(peer_stream: TcpStream, config: &ClientConfig,
                             tls_config: &ClientTlsConfig) {
    let tls_connector = tls_config
        .tls_connector(Uri::from_static("localhost"))
        .unwrap_or_else(|e| { panic!("tls_connector build err: {}", e) });

    let addr_conn: SocketAddr =
        format!("{}:{}", config.server_host, config.server_port)
            .parse()
            .unwrap_or_else(|e| { panic!("parse server addr err: {}", e) });

    let tcp_stream = TcpStream::connect(addr_conn)
        .await.unwrap_or_else(|e| { panic!("tcp stream connect err: {}", e) });

    let tls_stream = tls_connector.connect(tcp_stream)
        .await.unwrap_or_else(|e| { panic!("tls stream connect err: {}", e) });

    info!("client: tls conn established");

    let (mut peer_stream_reader, mut peer_stream_writer) = peer_stream.into_split();
    let (mut tls_stream_reader, mut tls_stream_writer) = tokio::io::split(tls_stream);

    let fut1 = tokio::spawn(async move {
        tokio::io::copy(&mut peer_stream_reader, &mut tls_stream_writer).await
            .unwrap_or_else(|e| { panic!("copy [peer->tls] err: {}", e) });
    });

    let fut2 = tokio::spawn(async move {
        tokio::io::copy(&mut tls_stream_reader, &mut peer_stream_writer).await
            .unwrap_or_else(|e| { panic!("copy [tls->peer] err: {}", e) });
    });

    let (_, _) = tokio::join!(fut1, fut2);
}

#[tokio::main]
async fn main() {
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

        process_peer_stream(peer_stream, &config, &tls_config).await;
    }
}
