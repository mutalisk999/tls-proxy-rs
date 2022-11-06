use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Read;

const CONFIG_FILE_NAME: &'static str = "server.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub server_key: String,
    pub server_cert: String,
    pub ca_cert: String,
}

impl ServerConfig {
    pub fn from_json_str(json_str: &str) -> ServerConfig {
        let server_config: ServerConfig = serde_json::from_str(json_str)
            .expect("invalid json str");

        server_config
    }
}

pub fn load_entire_file_content(file_name: &str) -> String {
    let mut config_file = File::open(file_name)
        .expect(&*format!("{} not found", file_name));

    let mut json_str = String::new();
    config_file.read_to_string(&mut json_str)
        .expect(&*format!("{} read to string error", file_name));

    json_str
}

#[test]
fn test_load_config() {
    let json_str = load_entire_file_content(CONFIG_FILE_NAME);
    println!("json_str: {:?}", json_str)
}

#[test]
fn test_deserialize_json_str() {
    let json_str = load_entire_file_content(CONFIG_FILE_NAME);
    let config = ServerConfig::from_json_str(&json_str);
    println!("config: {:?}", config);
}