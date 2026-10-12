use hbb_common::{
    config::{APP_NAME, OVERWRITE_SETTINGS},
    proxy::{Proxy, ProxyError},
    tls::{upsert_tls_cache, TlsType},
};
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::{rustls, TlsAcceptor};

const TIMEOUT: u64 = 3_000;

fn tls_acceptor() -> TlsAcceptor {
    let cert = CertificateDer::from_pem_slice(include_bytes!("data/websocket-cert.pem")).unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("data/websocket-key.pem")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

async fn https_connection(tls_type: TlsType, fixed_local_port: bool) {
    *APP_NAME.write().unwrap() = format!("RustDesk-proxy-review-{}", std::process::id());
    OVERWRITE_SETTINGS
        .write()
        .unwrap()
        .insert("allow-insecure-tls-fallback".into(), "Y".into());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    upsert_tls_cache(&url, tls_type, true);
    let local = if fixed_local_port {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Some(reserved.local_addr().unwrap())
    } else {
        None
    };
    let server = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.unwrap();
        let mut stream = tls_acceptor().accept(tcp).await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            assert!(headers.len() < 4096);
            headers.push(stream.read_u8().await.unwrap());
        }
        assert!(headers.starts_with(b"CONNECT relay.invalid:21117 HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut data = [0; 4];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"ping");
        stream.write_all(b"pong").await.unwrap();
        stream.flush().await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "an unused second TCP connection was opened"
        );
        peer
    });
    let proxy = Proxy::new(url, TIMEOUT).unwrap();
    let framed = proxy.connect("relay.invalid:21117", local).await.unwrap();
    let actual_local = framed.1;
    if let Some(local) = local {
        assert_eq!(actual_local, local);
    }
    let mut stream = framed.0.into_inner();
    stream.write_all(b"ping").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 4];
    timeout(
        Duration::from_millis(TIMEOUT),
        stream.read_exact(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&reply, b"pong");
    assert_eq!(server.await.unwrap(), actual_local);
}

#[tokio::test]
async fn https_rustls_reuses_initial_connection() {
    https_connection(TlsType::Rustls, false).await;
}

#[tokio::test]
async fn https_nativetls_reuses_initial_connection() {
    https_connection(TlsType::NativeTls, false).await;
}

#[tokio::test]
async fn https_rustls_with_fixed_local_port() {
    https_connection(TlsType::Rustls, true).await;
}

#[tokio::test]
async fn https_nativetls_with_fixed_local_port() {
    https_connection(TlsType::NativeTls, true).await;
}

#[tokio::test]
async fn https_reconnects_for_tls_fallback() {
    *APP_NAME.write().unwrap() = format!("RustDesk-proxy-review-{}", std::process::id());
    OVERWRITE_SETTINGS
        .write()
        .unwrap()
        .insert("allow-insecure-tls-fallback".into(), "Y".into());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        // Reject both Rustls attempts so the uncached route must reach NativeTls.
        for _ in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            drop(tcp);
        }
        let (tcp, _) = listener.accept().await.unwrap();
        assert!(tls_acceptor().accept(tcp).await.is_err());
    });
    let proxy = Proxy::new(&url, TIMEOUT).unwrap();
    let error = proxy
        .connect("relay.invalid:21117", None)
        .await
        .err()
        .unwrap();
    // The third connection reaches NativeTls and still rejects the untrusted identity.
    assert!(
        matches!(
            error.downcast_ref::<ProxyError>(),
            Some(ProxyError::NativeTlsError(_))
        ),
        "{}",
        error
    );
    timeout(Duration::from_millis(TIMEOUT), server)
        .await
        .unwrap()
        .unwrap();
}
