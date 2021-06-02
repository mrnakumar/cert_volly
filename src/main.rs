use chrono::Utc;
use openssl::asn1::Asn1Time;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use std::env;
use std::io::{Error, ErrorKind, Result};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() -> Result<()> {
    return match parse_command_line_arguments() {
        Ok(CommandLineArguments { domain, port }) => {
            let address = format!("{}:{}", domain, port);
            let address = address.to_socket_addrs();
            if let Err(_) = address {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid IPAddress/Domain",
                ));
            };
            let address = address?.as_slice()[0];
            let tcp_stream = TcpStream::connect_timeout(&address, Duration::from_secs(60))?;
            let mut ctx = SslConnector::builder(SslMethod::tls()).unwrap();
            ctx.set_verify(SslVerifyMode::NONE);
            let ctx = ctx.build();
            let stream_result = ctx.connect(&domain, &tcp_stream);
            if let Err(e) = &stream_result {
                eprintln!("Failed to connect. Is the domain and port correct? {:?}", e);
                return Err(Error::new(ErrorKind::NotConnected, ""));
            }
            let mut stream = stream_result.unwrap();
            match stream.ssl().peer_certificate() {
                Some(c) => {
                    let na = c.not_after();
                    let now = Utc::now().timestamp();
                    let remaining = Asn1Time::from_unix(now).unwrap().diff(na).unwrap().days;
                    println!(
                        "The certificate expires in {} days. It is valid till {}",
                        remaining, na
                    );
                    if remaining < 20 {
                        println!("Only {} days left", remaining);
                    }
                }
                None => eprintln!("Peer has no certificate!"),
            }
            shutdown_ssl(&mut stream);
            Ok(())
        }
        Err(e) => Err(e),
    };
}

struct CommandLineArguments {
    domain: String,
    port: u32,
}

fn parse_command_line_arguments() -> Result<CommandLineArguments> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 2 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "USAGES: <domain> <SSL port>",
        ));
    }
    let domain = &arguments[0];
    match &arguments[1].parse::<u32>() {
        Ok(port) => Ok(CommandLineArguments {
            domain: domain.clone(),
            port: *port,
        }),
        Err(e) => Err(Error::new(ErrorKind::InvalidInput, e.to_string())),
    }
}

fn shutdown_ssl(stream: &mut SslStream<&TcpStream>) -> () {
    match stream.shutdown() {
        Ok(sr) => match sr {
            _ => match stream.shutdown() {
                Ok(_) => println!("Shutdown finished"),
                Err(_) => println!("Couldn't shutdown stream"),
            },
        },
        Err(_) => eprintln!("Failed to shutdown stream"),
    }
}
