pub use native_tls::TlsStream;
use native_tls::{HandshakeError as TlsHandshakeError, TlsConnector};
use std::net::TcpStream;

pub use crate::stream::Stream as StreamSwitcher;
/// TCP stream switcher (plain/TLS).
pub type AutoStream = StreamSwitcher<TcpStream, TlsStream<TcpStream>>;

use crate::error::Result;
use crate::stream::Mode;

pub fn wrap_stream(stream: TcpStream, domain: &str, mode: Mode) -> Result<AutoStream> {
    match mode {
        Mode::Plain => Ok(StreamSwitcher::Plain(stream)),
        Mode::Tls => {
            let connector = TlsConnector::builder().build()?;
            connector
                .connect(domain, stream)
                .map_err(|e| match e {
                    TlsHandshakeError::Failure(f) => f.into(),
                    TlsHandshakeError::WouldBlock(_) => {
                        panic!("Bug: TLS handshake not blocked")
                    }
                })
                .map(StreamSwitcher::Tls)
        }
    }
}
