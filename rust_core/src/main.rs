extern crate libc;
use std::{
    io::Read,
    net::{TcpStream, UdpSocket},
    time::Duration,
};

#[link(name = "packet", kind = "dylib")]
extern "C" {
    fn send_packet(
        src_ip: *const libc::c_char,
        dst_ip: *const libc::c_char,
        port: libc::c_int,
        proto: libc::c_int,
    ) -> libc::c_int;
}

#[derive(Debug)]
pub enum ScanError {
    SocketError,
    InvalidProtocol,
    SendFailed,
    IoError(std::io::Error),
}

impl From<std::io::Error> for ScanError {
    fn from(value: std::io::Error) -> Self {
        ScanError::IoError(value)
    }
}

pub fn scan_port(target: &str, port: u16, proto: &str) -> Result<(bool, String), ScanError> {
    let proto_num = match proto {
        "tcp" => 0,
        "udp" => 1,
        _ => return Err(ScanError::InvalidProtocol),
    };

    let src_ip = std::ffi::CString::new("192.168.1.100").unwrap();
    let dst_ip = std::ffi::CString::new(target).unwrap();

    let result = unsafe {
        send_packet(
            src_ip.as_ptr(),
            dst_ip.as_ptr(),
            port as libc::c_int,
            proto_num,
        )
    };

    match result {
        0 => {}
        -1 => return Err(ScanError::SocketError),
        -2 => return Err(ScanError::InvalidProtocol),
        _ => return Err(ScanError::SendFailed),
    };

    let mut banner = String::new();

    match proto {
        "tcp" => {
            let mut stream = TcpStream::connect((target, port))?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;

            let mut buffer = [0; 1024];
            match stream.read(&mut buffer) {
                Ok(size) => {
                    banner = String::from_utf8_lossy(&buffer[..size]).to_string();
                    Ok((true, banner))
                }
                Err(e) => Err(ScanError::IoError(e)),
            }
        }
        "udp" => {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.set_read_timeout(Some(Duration::from_secs(2)))?;

            // Protocol-specific payloads
            let payload = match port {
                // DNS query
                53 => vec![
                    0xAA, 0xAA, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
                    0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00,
                    0x01, 0x00, 0x01,
                ],
                // NTP request
                123 => vec![
                    0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                // SNMP query
                161 => vec![
                    0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63,
                    0xA0, 0x1C, 0x02, 0x04, 0x7A, 0x6B, 0x08, 0x8B, 0x02, 0x01, 0x00, 0x02, 0x01,
                    0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01,
                    0x01, 0x00, 0x05, 0x00,
                ],
                // Default empty payload
                _ => vec![],
            };

            socket.send_to(&payload, (target, port))?;

            let mut buffer = [0; 1024];
            match socket.recv_from(&mut buffer) {
                Ok((size, _)) => {
                    banner = String::from_utf8_lossy(&buffer[..size])
                        .replace('\0', "")
                        .trim()
                        .to_string();
                    Ok((true, banner))
                }
                Err(_) => Ok((false, String::new())), // timeout no response
            }
        }
        _ => unreachable!(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 4 {
        eprintln!("Usage: {} <target> <port> <protocol>", args[0]);
        std::process::exit(1);
    }

    match scan_port(&args[1], args[2].parse().unwrap(), &args[3]) {
        Ok((open, banner)) => {
            if open {
                println!(
                    "{{\"port\": {}, \"banner\": \"{}\"}}",
                    args[2],
                    banner.escape_default()
                );
            } else {
                println!("closed")
            }
        }
        Err(e) => eprintln!("Error: {e:?}"),
    }
}
