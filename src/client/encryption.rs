
#[cfg(feature = "tls-rustls")]
#[path = "encryption/rustls.rs"]
mod tls;

#[cfg(all(feature = "tls", not(feature = "tls-rustls")))]
#[path = "encryption/native_tls.rs"]
mod tls;

#[cfg(not(any(feature = "tls", feature = "tls-rustls")))]
mod tls {
    use std::net::TcpStream;

    use crate::error::{Error, Result};
    use crate::stream::Mode;

    /// TLS support is nod compiled in, this is just standard `TcpStream`.
    pub type AutoStream = TcpStream;

    pub fn wrap_stream(stream: TcpStream, _domain: &str, mode: Mode) -> Result<AutoStream> {
        match mode {
            Mode::Plain => Ok(stream),
            Mode::Tls => Err(Error::Url("TLS support not compiled in.".into())),
        }
    }
}

pub use self::tls::*;
