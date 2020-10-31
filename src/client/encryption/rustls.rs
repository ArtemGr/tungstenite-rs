pub use native_tls::TlsStream;
use rustls::{ClientSession, ClientConfig};
pub use rustls::StreamOwned;
use webpki::DNSNameRef;
use std::net::TcpStream;
use std::sync::Arc;

pub use crate::stream::Stream as StreamSwitcher;
/// TCP stream switcher (plain/TLS).
pub type AutoStream = StreamSwitcher<TcpStream, StreamOwned<ClientSession, TcpStream>>;

use crate::error::Result;
use crate::stream::Mode;

pub fn wrap_stream(stream: TcpStream, domain: &str, mode: Mode) -> Result<AutoStream> {
    match mode {
        Mode::Plain => Ok(StreamSwitcher::Plain(stream)),
        Mode::Tls => {
            let domain = DNSNameRef::try_from_ascii_str(domain)?;
            let mut config = ClientConfig::new();
            config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            let session = ClientSession::new(&Arc::new(config), domain);
            Ok(AutoStream::Tls(StreamOwned::new(session, stream)))
        }
    }
}
