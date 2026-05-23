use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fred::types::config::ReplicaFilter;
use fred::types::config::Server;
use parking_lot::RwLock;
use tokio::time::Instant;
use tracing::debug;

/// Filters calls to replicas based on a filter() fn that returns true if there's a routeable
/// replica in the replicas cache. Replicas are routeable when we're able to make a TCP Connection
/// to them. We cache whether we were able to connect for 5 minutes. This applies to each replica,
/// not all replicas as a unit, so we can have some replicas fail and yet still route to the others
///
/// NOTE: filtering happens before any actual connections are made by our redis client (fred), so
/// we shouldn't see any connections errors from replicas that have been filtered out
#[derive(Default, Debug)]
pub(crate) struct RouteableReplicaFilter {
    replicas: Arc<RwLock<HashMap<String, Replica>>>,
}

#[derive(Debug)]
struct Replica {
    expires: Instant,
    routeable: bool,
}

#[async_trait::async_trait]
impl ReplicaFilter for RouteableReplicaFilter {
    // WARN: this is a hot path for fred, keep the instrumentation to trace-level
    #[tracing::instrument(level = "trace")]
    async fn filter(&self, _primary: &Server, replica: &Server) -> bool {
        let addr = format!("{}:{}", replica.host, replica.port);
        // guard block so we drop the read guard before crossing the await boundary below (RwLock
        // not Send)
        let cached = {
            let replicas = self.replicas.read();
            replicas.get(&addr).map(|rep| (rep.expires, rep.routeable))
        };

        // if we have a replica
        if let Some((expires, routeable)) = cached {
            // that hasn't expired yet
            if expires > Instant::now() {
                // return its saved routeability
                return routeable;
            }
            debug!("redis replica filter cache: entry for {addr} expired");
        }

        // otherwise, we try to test routeability via tcp connect
        let routeable = tokio::time::timeout(
            // with a short timeout, 250ms
            Duration::from_millis(250),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map(|res| res.is_ok())
        .inspect_err(|_e| debug!("{addr} is being broadcast as part of redis but is not currently routeable, which may be intentional if using centralized or high-availabitliy setups with internal IPs for certain nodes or might represent a misconfiguration or infrastructure failure"))
        .unwrap_or(false);

        let mut replicas = self.replicas.write();
        replicas.insert(
            addr,
            Replica {
                // 5 minute cache
                expires: Instant::now() + Duration::from_secs(300),
                routeable,
            },
        );

        routeable
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::rustls::RootCertStore;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::ServerName;

    use super::*;
    use crate::configuration::load_certs;
    use crate::configuration::load_key;

    fn dummy_primary() -> Server {
        Server::new("127.0.0.1", 6379)
    }

    fn server(port: u16) -> Server {
        Server::new("127.0.0.1", port)
    }

    fn seed_cache(filter: &RouteableReplicaFilter, port: u16, routeable: bool, expires: Instant) {
        let addr = format!("127.0.0.1:{port}");
        filter
            .replicas
            .write()
            .insert(addr, Replica { expires, routeable });
    }

    #[tokio::test]
    async fn reachable_replica_returns_true() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let filter = RouteableReplicaFilter::default();
        assert!(filter.filter(&dummy_primary(), &server(port)).await);
    }

    #[tokio::test]
    async fn unreachable_replica_returns_false() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let filter = RouteableReplicaFilter::default();
        assert!(!filter.filter(&dummy_primary(), &server(port)).await);
    }

    #[tokio::test]
    async fn cached_result_is_returned_without_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let filter = RouteableReplicaFilter::default();
        assert!(filter.filter(&dummy_primary(), &server(port)).await);

        // drop the listener — port is now unreachable
        drop(listener);

        // should still return true from cache
        assert!(filter.filter(&dummy_primary(), &server(port)).await);
    }

    #[tokio::test]
    async fn result_is_cached_after_filter() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let filter = RouteableReplicaFilter::default();
        filter.filter(&dummy_primary(), &server(port)).await;

        let replicas = filter.replicas.read();
        let addr = format!("127.0.0.1:{port}");
        let entry = replicas.get(&addr).expect("entry should be cached");
        assert!(entry.routeable);
        assert!(entry.expires > Instant::now());
    }

    #[tokio::test]
    async fn expired_cache_triggers_fresh_connect() {
        // seed with an already-expired entry that says routeable=true
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let filter = RouteableReplicaFilter::default();
        let expired = Instant::now() - Duration::from_secs(1);
        seed_cache(&filter, port, true, expired);

        // cache says true, but it's expired — fresh connect will fail
        assert!(!filter.filter(&dummy_primary(), &server(port)).await);
    }

    #[tokio::test]
    async fn unexpired_cache_is_used() {
        // seed with a not-yet-expired entry, no listener needed
        let filter = RouteableReplicaFilter::default();
        let port = 1; // doesn't matter, cache will be hit
        let future = Instant::now() + Duration::from_secs(300);
        seed_cache(&filter, port, true, future);

        assert!(filter.filter(&dummy_primary(), &server(port)).await);
    }

    #[tokio::test]
    async fn unexpired_false_cache_is_used() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // seed with routeable=false even though the port is actually reachable
        let filter = RouteableReplicaFilter::default();
        let future = Instant::now() + Duration::from_secs(300);
        seed_cache(&filter, port, false, future);

        // cache wins — returns false despite the port being open
        assert!(!filter.filter(&dummy_primary(), &server(port)).await);
    }

    #[tokio::test]
    async fn separate_replicas_cached_independently() {
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();

        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_b = listener_b.local_addr().unwrap().port();
        drop(listener_b);

        let filter = RouteableReplicaFilter::default();
        assert!(filter.filter(&dummy_primary(), &server(port_a)).await);
        assert!(!filter.filter(&dummy_primary(), &server(port_b)).await);

        let replicas = filter.replicas.read();
        assert_eq!(replicas.len(), 2);
    }

    #[tokio::test]
    async fn expired_entry_gets_replaced() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let filter = RouteableReplicaFilter::default();
        let expired = Instant::now() - Duration::from_secs(1);
        seed_cache(&filter, port, false, expired);

        // expired false entry should be replaced by a fresh true result
        assert!(filter.filter(&dummy_primary(), &server(port)).await);

        let replicas = filter.replicas.read();
        let addr = format!("127.0.0.1:{port}");
        let entry = replicas.get(&addr).unwrap();
        assert!(entry.routeable);
        assert!(entry.expires > Instant::now());
    }

    #[tokio::test]
    async fn connect_timeout_returns_false() {
        let filter = RouteableReplicaFilter::default();
        let primary = dummy_primary();
        // this is a special non-routeable address (designated for use in documentaton/examples),
        // rfc 5737, but if this flakes a bunch in ci/cd, we can mark it ignore and just keep it
        // locally
        let replica = Server::new("192.0.2.1", 1);

        let start = Instant::now();
        let result = filter.filter(&primary, &replica).await;
        let elapsed = start.elapsed();

        assert!(!result);
        // Should have waited for the 250ms timeout, not returned instantly
        assert!(
            elapsed >= Duration::from_millis(200),
            "expected timeout (~250ms), but returned in {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn connect_timeout_result_is_cached() {
        let filter = RouteableReplicaFilter::default();
        let primary = dummy_primary();
        let replica = Server::new("192.0.2.1", 1);

        filter.filter(&primary, &replica).await;

        // Second call should return from cache instantly, not wait for timeout
        let start = Instant::now();
        let result = filter.filter(&primary, &replica).await;
        let elapsed = start.elapsed();

        assert!(!result);
        assert!(
            elapsed < Duration::from_millis(50),
            "expected instant cache hit, but took {elapsed:?}"
        );
    }

    // ---------------------------------------------------------------------------------------
    // TLS-blindness proofs.
    //
    // The filter performs a plain TCP probe (line 53-61). Production redis.rs:305-318
    // configures fred with `TlsConnector::Rustls(...)`, but the filter at redis.rs:444
    // is `Default`-constructed with no TLS awareness — L4 reachability is treated as
    // routeability.
    //
    // Real-world failure modes this manifests as:
    //   - TLS sidecar (stunnel, envoy, istio) crashes or is restarted while the L4
    //     listener (or LB in front of it) keeps answering TCP. fred's routing table
    //     keeps the replica in rotation; every command to it fails at TLS handshake
    //     until the 5-minute filter cache expires.
    //   - Certificate rotation drift: cert-manager / Vault rotates the replica's
    //     cert to a new CA the router's bundle hasn't caught up to, or the cert has
    //     expired. L4 is fine; TLS verification fails.
    //   - Cloud LB / NLB health checks are L4-only, so the LB keeps a TLS-broken
    //     backend in rotation. The filter inherits the same blind spot.
    //
    // The tests below encode the *desired* post-fix behavior (`routeable == false`
    // for TLS-unroutable replicas) and use `#[should_panic(expected = ...)]` so they
    // pass today (the assertion fails under the current TCP-only probe) and break
    // loudly when a TLS-aware probe lands. When that happens, drop the `should_panic`
    // attributes — the underlying assertions already express the right invariant.
    // ---------------------------------------------------------------------------------------

    /// Production-style strict TLS client config: empty root store (does not trust the
    /// self-signed test cert), no client auth. Mirrors what `generate_tls_client_config`
    /// would build for a real deployment where the configured CA does not chain to the
    /// replica's served cert.
    fn strict_tls_client_config() -> ClientConfig {
        ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth()
    }

    /// Models a "cert mismatch" replica — e.g., post-rotation drift where the replica
    /// serves a cert signed by a CA the router doesn't trust, an expired cert, or a
    /// cert with a wrong SAN. Serves the checked-in self-signed cert over a minimal
    /// TLS acceptor (no hyper, no ALPN — intentionally separate from the helper in
    /// `services/http/tests.rs::tls_server`).
    async fn spawn_tls_only_listener() -> u16 {
        let cert_pem = include_str!("../services/http/testdata/server_self_signed.crt");
        let key_pem = include_str!("../services/http/testdata/server.key");
        let certs = load_certs(cert_pem).expect("load self-signed cert");
        let key = load_key(key_pem).expect("load test key");

        let tls_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("build server tls config");
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // The client never trusts our cert, so the handshake will fail.
                    // Either outcome is fine for the test — we just need a TLS-only
                    // peer that refuses plain Redis protocol.
                    let _ = acceptor.accept(stream).await;
                });
            }
        });

        port
    }

    /// Models a "TLS terminator dead, L4 still alive" replica — e.g., a crashed
    /// stunnel/envoy sidecar, a Redis instance restarted without `--tls-port`, or an
    /// LB that keeps a TLS-broken backend in rotation because its health check is
    /// L4-only. Accepts the TCP handshake and immediately shuts the socket down.
    async fn spawn_tcp_only_listener_that_rejects_tls() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream.shutdown().await;
            }
        });

        port
    }

    #[tokio::test]
    #[should_panic(expected = "filter should refuse a replica that cannot complete TLS handshake")]
    async fn tcp_only_probe_admits_replica_that_rejects_tls_handshake() {
        let port = spawn_tcp_only_listener_that_rejects_tls().await;

        // Precondition check: this is genuinely a "TLS-dead, L4-alive" port — a real
        // TLS-configured fred client cannot use it. Production analog: a stunnel/envoy
        // sidecar crashed, or Redis came back from a restart without TLS configured.
        let connector = TlsConnector::from(Arc::new(strict_tls_client_config()));
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let handshake = connector.connect(server_name, stream).await;
        assert!(
            handshake.is_err(),
            "precondition: TLS handshake should fail against a TCP-only listener"
        );

        // Now exercise the filter the production code uses. Today it returns `true`
        // because it only probes L4. The assertion below encodes the desired
        // post-fix behavior; it fails under current behavior and is caught by
        // `#[should_panic]`.
        let filter = RouteableReplicaFilter::default();
        let routeable = filter.filter(&dummy_primary(), &server(port)).await;
        assert!(
            !routeable,
            "filter should refuse a replica that cannot complete TLS handshake"
        );
    }

    #[tokio::test]
    #[should_panic(expected = "filter should refuse a replica whose cert cannot be verified")]
    async fn tcp_only_probe_admits_replica_with_untrusted_tls_cert() {
        let port = spawn_tls_only_listener().await;

        // Precondition check: this models post-rotation drift / expired cert — the
        // router's CA bundle does not chain to what the replica serves, so the
        // production TLS client aborts the handshake.
        let connector = TlsConnector::from(Arc::new(strict_tls_client_config()));
        let stream = TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let handshake = connector.connect(server_name, stream).await;
        assert!(
            handshake.is_err(),
            "precondition: strict-root-store TLS client should reject the self-signed cert"
        );

        // The filter, which has no TLS context, still admits this replica.
        let filter = RouteableReplicaFilter::default();
        let routeable = filter.filter(&dummy_primary(), &server(port)).await;
        assert!(
            !routeable,
            "filter should refuse a replica whose cert cannot be verified"
        );
    }
}
