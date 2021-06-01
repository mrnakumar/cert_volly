use chrono::Utc;
use openssl::asn1::Asn1Time;
use openssl::ssl::{SslConnector, SslMethod};
use std::net::TcpStream;
fn main() -> std::io::Result<()> {
    let stream = TcpStream::connect("mrnakumar.com:443")?;
    let ctx = SslConnector::builder(SslMethod::tls()).unwrap();
    //ctx.set_verify(SslVerifyMode::NONE);
    let ctx = ctx.build();
    let mut stream = ctx.connect("mrnakumar.com", stream).unwrap();
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
        Ok(_) => println!("closed stream"),
        Err(_) => eprintln!("failed to shutdown stream"),
    }
    Ok(())
}
