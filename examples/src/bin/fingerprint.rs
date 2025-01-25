//! the ja4 fingerprint should be:
//! first: proto, tlsVersion, sniMode, numSuites, numExtensions, firstALPN
//! second: sha256(suites)
//! third: sha256(extensions)

/// results of us
// chrome108: t13d1516h1_8daaf6152771_5fb3489db586
// edge106: t13d1616h1_e72c3b3287f1_5fb3489db586
// firefox105: t13d1715h1_5b57614c22b0_5a7a167d0339
// safari17: t13d2014h1_a09f3c656075_f62623592221
// ios14: t13d2613h1_9f5fa85aebfd_fda70f8e401f

// results of utls: code(https://gist.github.com/hsqStephenZhang/464792650322426c619ace61bdbc5ff5)
// chrome115: t13d1515h2_8daaf6152771_e5627efa2ab1
// edge106: t13d1616h2_e72c3b3287f1_5fb3489db586
// firefox105: t13d1715h2_5b57614c22b0_5a7a167d0339
// safari16: t13d2014h2_a09f3c656075_f62623592221

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
    Edge106,
}

impl From<&str> for Fingerprint {
    fn from(s: &str) -> Self {
        match s {
            "chrome108" => Fingerprint::Chrome108,
            "firefox" => Fingerprint::Firefox,
            "safari" => Fingerprint::Safari,
            "edge106" => Fingerprint::Edge106,
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
        Fingerprint::Edge106 => rustls::craft::EDGE_106
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
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
