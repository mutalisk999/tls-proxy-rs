use std::error::Error;
use std::ops::{Shl, Add, Index};
// use hex;
use serde_json::Value;

const PROTOCOL_VERSION: u8 = 0x05;

pub fn get_methods_description(m: u8) -> &'static str {
    match m {
        0x0 => "NO AUTHENTICATION REQUIRED",
        0x01 => "GSSAPI",
        0x02 => "USERNAME/PASSWORD",
        0xff => "NO ACCEPTABLE METHODS",
        0x03..=0x7f => "IANA ASSIGNED",
        0x80..=0xfe => "RESERVED FOR PRIVATE METHODS",
        _ => ""
    }
}

pub fn parse_handshake_body(body: &Vec<u8>) -> Result<bool, Box<dyn Error>> {
    if body.len() <= 2 {
        return Err("invalid handshake body length")?;
    }
    if body.len() != Value::from(body[1] + 2) {
        return Err("invalid handshake body length")?;
    }
    if body.index(0) != &PROTOCOL_VERSION {
        return Err("only support socks5 protocol")?;
    }

    // check if method 'NO AUTHENTICATION REQUIRED' supported
    return if body[2..].contains(&0x0) {
        Ok(true)
    } else {
        Err("method 'NO AUTHENTICATION REQUIRED' not supported")?
    };
}

pub fn parse_request_body(body: &Vec<u8>) -> Result<(u8, u8, String, u16), Box<dyn Error>> {
    if body.len() <= 4 {
        return Err("invalid handshake body length")?;
    }
    if body.index(0) != &PROTOCOL_VERSION {
        return Err("only support socks5 protocol")?;
    }
    if body.index(1) != &0x01_u8 && body.index(1) != &0x02_u8 && body.index(1) != &0x03_u8 {
        return Err("invalid field CMD")?;
    }
    if body.index(2) != &0x0_u8 {
        return Err("invalid field RSV")?;
    }
    if body.index(3) != &0x01_u8 && body.index(3) != &0x03_u8 && body.index(3) != &0x04_u8 {
        return Err("invalid field ATYP")?;
    }

    return match body[3] {
        0x01 => {
            if body.len() != Value::from(10) {
                Err("invalid request body length")?
            } else {
                Ok(
                    (
                        body[1],
                        body[3],
                        format!("{}.{}.{}.{}", body[4], body[5], body[6], body[7]),
                        (body[8] as u16).shl(8) + body[9] as u16
                    )
                )
            }
        }
        0x03 => {
            if body.len() != (body[4] as usize).add(7) {
                Err("invalid request body length")?
            } else {
                Ok(
                    (
                        body[1],
                        body[3],
                        String::from_utf8_lossy(&body[5..5 + body[4] as usize]).to_string(),
                        (body[body[4] as usize + 5] as u16).shl(8) + body[body[4] as usize + 6] as u16
                    )
                )
            }
        }
        0x04 => {
            // if body.len() != Value::from(22) {
            //     Err("invalid request body length")?
            // } else {
            //     Ok(
            //         (
            //             body[1],
            //             body[3],
            //             format!("{}:{}:{}:{}:{}:{}:{}:{}", hex::encode(&body[4..6]), hex::encode(&body[6..8]), hex::encode(&body[8..10]), hex::encode(&body[10..12]), hex::encode(&body[12..14]), hex::encode(&body[14..16]), hex::encode(&body[16..18]), hex::encode(&body[18..20])),
            //             (body[20] as u16).shl(8) + body[21] as u16
            //         )
            //     )
            // }
            return Err("ip v6 not supported")?;
        }
        _ => {
            Err("could not reached")?
        }
    };
}

#[test]
fn test_get_methods_description() {
    let m = get_methods_description(0x0);
    println!("method: {:?}", m)
}
