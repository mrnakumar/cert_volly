use chrono::Utc;
use openssl::asn1::Asn1Time;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::env;
use std::io::{Error, ErrorKind};
use std::net::TcpStream;

fn main() -> std::io::Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.len() != 2 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "USAGES: <domain> <SSL port>",
        ));
    }
    let domain = &arguments[0];
    let port = &arguments[1];
    let tcp_stream = TcpStream::connect(format!("{}:{}", domain, port))?;
    let mut ctx = SslConnector::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::NONE);
    let ctx = ctx.build();
    let mut stream = ctx.connect(domain, &tcp_stream).unwrap();
    match stream.ssl().peer_certificate() {
        Some(c) => {
            let na = c.not_after();
            let now = Utc::now().timestamp();
            let remaining = Asn1Time::from_unix(now).unwrap().diff(na).unwrap().days;
            if remaining < 20 {
                println!("Only {} days left", remaining);
            } else {
                println!("You have got time");
            }
        }
        None => eprintln!("Peer has no certificate!"),
    }
    match stream.shutdown() {
        Ok(sr) => match sr {
            _ => match stream.shutdown() {
                Ok(_) => println!("Shutdown finished"),
                Err(_) => println!("Couldn't shutdown stream"),
            },
        },
        Err(_) => eprintln!("failed to shutdown stream"),
    }
    Ok(())
}
