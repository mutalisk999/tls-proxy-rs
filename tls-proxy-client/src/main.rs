extern crate tokio;

mod config;

use std::net::SocketAddr;
use tokio::net::TcpSocket;
use std::error::Error;
use config::{load_entire_file_content, ClientConfig};
use log::{error, info};

use crate::config::CONFIG_FILE_NAME;

fn reuse_socket(s: &TcpSocket) -> Result<(), Box<dyn Error>> {
    s.set_reuseaddr(true)?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let json_str = load_entire_file_content(CONFIG_FILE_NAME);
    let config = ClientConfig::from_json_str(&json_str);

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
        let (mut tcp_stream, peer_addr) = r.unwrap();
        info!("connection of peer from {}", peer_addr);

        tokio::spawn(async move {});
    }
}
