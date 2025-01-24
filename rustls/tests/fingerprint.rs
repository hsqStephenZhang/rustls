#[cfg(test)]
mod tests {

    #[test]
    fn test_fingerprint() {
        let f = rustls::craft::CHROME_108
            .test_alpn_http1
            .builder()
            .get_fingerprint();
        println!("{:?}", f);
    }
}
