//! the ja4 fingerprint should be:
//! chrome108: t13d1516h1_8daaf6152771_5fb3489db586
//! firefox: t13d1516h1_8daaf6152771_5fb3489db586
use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use clap::Parser;
use rustls::RootCertStore;

#[derive(Debug, Clone)]
enum Fingerprint {
    Chrome108,
    Firefox,
    Safari,
}

impl From<&str> for Fingerprint {
    fn from(s: &str) -> Self {
        match s {
            "chrome108" => Fingerprint::Chrome108,
            "firefox" => Fingerprint::Firefox,
            "safari" => Fingerprint::Safari,
            _ => panic!("Invalid fingerprint"),
        }
    }
}

#[derive(Debug, Parser)]
#[clap(version)]
struct Opts {
    #[clap(short, long, default_value = "chrome108")]
    fingerprint: Fingerprint,

    #[clap(short, long, default_value = "false")]
    alpn: bool,
}

fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned(),
    );
    let opts = Opts::parse();

    let fingerprint = match opts.fingerprint {
        Fingerprint::Chrome108 => rustls::craft::CHROME_108
            .get(opts.alpn)
            .builder(),
        Fingerprint::Firefox => rustls::craft::FIREFOX_105
            .get(opts.alpn)
            .builder(),
        Fingerprint::Safari => rustls::craft::SAFARI_17_1
            .get(opts.alpn)
            .builder(),
    };

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .with_fingerprint(fingerprint);

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = "tls.peet.ws".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("tls.peet.ws:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(concat!("GET /api/all HTTP/1.1\r\n", "\r\n").as_bytes())
        .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
