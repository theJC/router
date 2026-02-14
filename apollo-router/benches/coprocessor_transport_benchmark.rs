//! Benchmark comparing Unix Domain Socket (UDS) vs TCP transport performance
//! for coprocessor communication using HTTP/2 cleartext (h2c).
//!
//! Run with `cargo bench --bench coprocessor_transport_benchmark`

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::header::CONTENT_TYPE;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::io::AsyncBufReadExt;
use tokio::net::UnixListener;

const ROUTER_EXE: &str = env!("CARGO_BIN_EXE_router");

// Port constants
const TCP_COPROCESSOR_PORT: u16 = 45000;
const TCP_ROUTER_PORT: u16 = 45001;
const SUBGRAPH_PORT: u16 = 45002;

// Test parameters
const WARMUP_ITERATIONS: usize = 20000;  // 100x increase from 200
const MEASUREMENT_ITERATIONS: usize = 100000;  // 100x increase from 1000
const CONCURRENT_DURATION_SECS: u64 = 10;
const CONCURRENCY_LEVELS: &[usize] = &[100, 500, 1000, 2500, 5000];  // 100x increase
const BENCHMARK_RUNS: usize = 3;  // Number of runs to perform for each test
const OUTLIER_TRIM_PERCENT: usize = 1;  // Trim top/bottom 1% as outliers
const ROUTER_INITIAL_WARMUP_REQUESTS: usize = 5000;  // 100x increase from 50
const STABILIZATION_DELAY_MS: u64 = 5000;  // Increased to 5s for high-concurrency tests

#[derive(Debug, Clone, Copy)]
enum Transport {
    Tcp,
    Uds,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Tcp => write!(f, "TCP"),
            Transport::Uds => write!(f, "UDS"),
        }
    }
}

#[derive(Debug, Clone)]
struct LatencyStats {
    min: Duration,
    max: Duration,
    mean: Duration,
    std_dev: Duration,
    p50: Duration,
    p95: Duration,
    p99: Duration,
    router_cpu_time_ms: f64,
}

#[derive(Debug)]
struct ThroughputStats {
    total_requests: u64,
    elapsed: Duration,
    requests_per_sec: f64,
    router_cpu_time_ms: f64,
    p50_latency: Duration,
    p95_latency: Duration,
    p99_latency: Duration,
    mean_latency: Duration,
}

struct ShutdownOnDrop(Option<tokio::sync::mpsc::Sender<()>>);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.try_send(());
        }
    }
}

/// Check if enterprise features are enabled via environment variables
fn enterprise_enabled() -> bool {
    matches!(
        (
            std::env::var("TEST_APOLLO_KEY"),
            std::env::var("TEST_APOLLO_GRAPH_REF"),
        ),
        (Ok(_), Ok(_))
    )
}

/// Get CPU time in milliseconds for a given PID by reading /proc/[pid]/stat
fn get_cpu_time_ms(pid: u32) -> Result<f64, Box<dyn std::error::Error>> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = std::fs::read_to_string(stat_path)?;

    // Parse /proc/[pid]/stat format
    // Format: pid (comm) state ppid ... utime stime cutime cstime ...
    // The command name can contain spaces and parentheses, so we need to handle that

    // Find the last ')' to skip the command name field
    let comm_end = stat_content.rfind(')').ok_or("Invalid stat format")?;
    let after_comm = &stat_content[comm_end + 1..];
    let parts: Vec<&str> = after_comm.split_whitespace().collect();

    if parts.len() < 13 {
        return Err("Invalid /proc/[pid]/stat format".into());
    }

    // After skipping pid and comm, field indices are:
    // 0: state, 1: ppid, ..., 11: utime, 12: stime
    let utime: u64 = parts[11].parse()?;
    let stime: u64 = parts[12].parse()?;

    // Clock ticks per second is typically 100 on Linux (sysconf(_SC_CLK_TCK))
    // We'll use 100 as a reasonable default since we can't easily call sysconf from Rust
    let clock_ticks_per_sec = 100.0;

    // Convert to milliseconds
    let total_ticks = (utime + stime) as f64;
    let cpu_time_ms = (total_ticks / clock_ticks_per_sec) * 1000.0;

    Ok(cpu_time_ms)
}

/// Main benchmark entry point
#[tokio::main]
async fn main() {
    assert!(
        ROUTER_EXE.contains("release"),
        "Router executable must be built in release mode"
    );

    // Check if enterprise features are enabled
    if !enterprise_enabled() {
        println!("=================================================================");
        println!("Coprocessor Transport Performance Benchmark");
        println!("=================================================================");
        println!("\nSKIPPED: This benchmark requires enterprise features.");
        println!("Please set TEST_APOLLO_KEY and TEST_APOLLO_GRAPH_REF environment variables.");
        println!("\nExample:");
        println!("  export TEST_APOLLO_KEY=your_key");
        println!("  export TEST_APOLLO_GRAPH_REF=your_graph_ref");
        println!("  cargo bench --bench coprocessor_transport_benchmark");
        println!("=================================================================");
        return;
    }

    println!("=================================================================");
    println!("Coprocessor Transport Performance Benchmark");
    println!("=================================================================");
    println!("Configuration:");
    println!("  - Protocol: HTTP/2 cleartext (h2c)");
    println!("  - Payload size: ~1KB GraphQL request");
    println!("  - Sequential iterations: {}", MEASUREMENT_ITERATIONS);
    println!(
        "  - Concurrent duration: {}s per test",
        CONCURRENT_DURATION_SECS
    );
    println!("  - Concurrent levels: {:?}", CONCURRENCY_LEVELS);
    println!("  - Benchmark runs per test: {}", BENCHMARK_RUNS);
    println!("  - Outlier trimming: {}%", OUTLIER_TRIM_PERCENT);
    println!();
    println!("IMPORTANT: For consistent results:");
    println!("  - Close other applications");
    println!("  - Run on AC power (not battery)");
    println!("  - Disable background services (Spotlight, Time Machine, etc.)");
    println!();

    // Run sequential latency benchmarks with multiple runs
    println!("Running sequential latency benchmarks...");
    println!();

    // TCP: Run multiple times and take median
    let mut tcp_runs = Vec::new();
    for run in 0..BENCHMARK_RUNS {
        eprintln!("TCP sequential run {}/{}", run + 1, BENCHMARK_RUNS);
        let stats = benchmark_sequential_latency(Transport::Tcp)
            .await
            .expect("TCP sequential benchmark failed");
        tcp_runs.push(stats);

        if run < BENCHMARK_RUNS - 1 {
            eprintln!("Stabilizing system...");
            tokio::time::sleep(Duration::from_millis(STABILIZATION_DELAY_MS)).await;
        }
    }
    // Use median run (middle result by mean latency)
    tcp_runs.sort_by_key(|s| s.mean);
    let tcp_latency = tcp_runs[BENCHMARK_RUNS / 2].clone();

    // Stabilization between TCP and UDS tests
    eprintln!("Stabilizing system between transports...");
    tokio::time::sleep(Duration::from_millis(STABILIZATION_DELAY_MS)).await;

    // UDS: Run multiple times and take median
    let mut uds_runs = Vec::new();
    for run in 0..BENCHMARK_RUNS {
        eprintln!("UDS sequential run {}/{}", run + 1, BENCHMARK_RUNS);
        let stats = benchmark_sequential_latency(Transport::Uds)
            .await
            .expect("UDS sequential benchmark failed");
        uds_runs.push(stats);

        if run < BENCHMARK_RUNS - 1 {
            eprintln!("Stabilizing system...");
            tokio::time::sleep(Duration::from_millis(STABILIZATION_DELAY_MS)).await;
        }
    }
    // Use median run (middle result by mean latency)
    uds_runs.sort_by_key(|s| s.mean);
    let uds_latency = uds_runs[BENCHMARK_RUNS / 2].clone();

    print_latency_results(&tcp_latency, &uds_latency);

    // Run concurrent throughput benchmarks
    println!("\nRunning concurrent throughput benchmarks...");
    println!();

    // Extra stabilization delay before concurrent tests to ensure ports are released
    eprintln!("Stabilizing system before concurrent tests (10 seconds)...");
    tokio::time::sleep(Duration::from_millis(10000)).await;

    let mut tcp_throughput_results = Vec::new();
    let mut uds_throughput_results = Vec::new();

    for &concurrency in CONCURRENCY_LEVELS {
        println!("Testing concurrency level: {}", concurrency);

        eprintln!("Running TCP benchmark for concurrency {}...", concurrency);
        let tcp_result = benchmark_concurrent_throughput(Transport::Tcp, concurrency)
            .await
            .expect("TCP concurrent benchmark failed");
        tcp_throughput_results.push((concurrency, tcp_result));

        // Stabilization delay between TCP and UDS
        eprintln!("Stabilizing system between TCP and UDS tests...");
        tokio::time::sleep(Duration::from_millis(STABILIZATION_DELAY_MS * 2)).await;

        eprintln!("Running UDS benchmark for concurrency {}...", concurrency);
        let uds_result = benchmark_concurrent_throughput(Transport::Uds, concurrency)
            .await
            .expect("UDS concurrent benchmark failed");
        uds_throughput_results.push((concurrency, uds_result));

        // Longer stabilization delay before next concurrency level to ensure all ports are released
        if concurrency != *CONCURRENCY_LEVELS.last().unwrap() {
            eprintln!("Stabilizing system before next concurrency level (10 seconds)...");
            tokio::time::sleep(Duration::from_millis(10000)).await;
        }
    }

    print_throughput_results(&tcp_throughput_results, &uds_throughput_results);
    print_csv_output(
        &tcp_latency,
        &uds_latency,
        &tcp_throughput_results,
        &uds_throughput_results,
    );

    println!("\n=================================================================");
    println!("Benchmark completed successfully!");
    println!("=================================================================");
}

/// Benchmark sequential latency for a given transport
async fn benchmark_sequential_latency(
    transport: Transport,
) -> Result<LatencyStats, Box<dyn std::error::Error>> {
    let payload = generate_test_payload();

    eprintln!("Starting servers for {} transport...", transport);

    // Start servers
    eprintln!("Spawning subgraph server...");
    let _subgraph = spawn_subgraph().await?;
    eprintln!("Subgraph server spawned");

    eprintln!("Spawning coprocessor server...");
    let (_coprocessor, socket_path) = match transport {
        Transport::Tcp => (spawn_tcp_coprocessor().await?, None),
        Transport::Uds => {
            let (guard, path) = spawn_uds_coprocessor().await?;
            (guard, Some(path))
        }
    };
    eprintln!("Coprocessor server spawned");

    // Verify UDS socket file exists
    if let Some(ref path) = socket_path {
        if let Err(e) = std::fs::metadata(path) {
            return Err(format!("Socket file {} not found: {}", path.display(), e).into());
        }
    }

    // Give servers a moment to fully bind and start listening
    eprintln!("Waiting for servers to be ready...");
    tokio::time::sleep(Duration::from_millis(500)).await;

    eprintln!("Spawning router...");
    let _router = spawn_router(transport, socket_path.as_deref()).await?;
    let router_pid = _router.id().ok_or("Failed to get router PID")?;
    eprintln!("Router spawned with PID {} and ready", router_pid);

    // Create HTTP client
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    // Extended router warmup: send initial requests to fully initialize
    // the router pipeline, coprocessor connection pool, and HTTP/2 streams
    eprintln!("Warming up router pipeline...");
    for _ in 0..ROUTER_INITIAL_WARMUP_REQUESTS {
        let _ = execute_query(&client, &payload).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await; // Let things settle

    // Standard warmup phase
    for _ in 0..WARMUP_ITERATIONS {
        execute_query(&client, &payload).await?;
    }

    // Get initial CPU time before measurement phase
    let cpu_start = get_cpu_time_ms(router_pid)?;

    // Measurement phase
    let mut latencies = Vec::with_capacity(MEASUREMENT_ITERATIONS);
    for i in 0..MEASUREMENT_ITERATIONS {
        let start = Instant::now();
        let response = execute_query(&client, &payload).await?;
        let latency = start.elapsed();

        let status = response.status();
        if !status.is_success() {
            eprintln!("Request {} failed with status: {}", i, status);
            // Try to read response body for more details
            let body_bytes = response.into_body().collect().await?.to_bytes();
            let body_str = String::from_utf8_lossy(&body_bytes);
            eprintln!("Response body: {}", body_str);
            return Err(format!("Request failed with status: {} - Body: {}",
                status, body_str).into());
        }

        latencies.push(latency);

        // Log progress every 10000 iterations (adjusted for 100x increase)
        if (i + 1) % 10000 == 0 {
            eprintln!("Completed {} iterations", i + 1);
        }
    }

    // Get final CPU time after measurement phase
    let cpu_end = get_cpu_time_ms(router_pid)?;
    let router_cpu_time_ms = cpu_end - cpu_start;

    // Calculate statistics with outlier trimming
    latencies.sort();

    // Trim outliers (remove top/bottom OUTLIER_TRIM_PERCENT%)
    let trim_count = (MEASUREMENT_ITERATIONS * OUTLIER_TRIM_PERCENT) / 100;
    let trimmed = if trim_count > 0 {
        &latencies[trim_count..MEASUREMENT_ITERATIONS - trim_count]
    } else {
        &latencies[..]
    };

    // Calculate mean on trimmed data
    let sum: Duration = trimmed.iter().sum();
    let mean = sum / (trimmed.len() as u32);

    // Calculate standard deviation
    let mean_f64 = mean.as_secs_f64();
    let variance: f64 = trimmed.iter()
        .map(|&d| {
            let diff = d.as_secs_f64() - mean_f64;
            diff * diff
        })
        .sum::<f64>() / (trimmed.len() as f64);
    let std_dev = Duration::from_secs_f64(variance.sqrt());

    Ok(LatencyStats {
        min: latencies[0],
        max: latencies[MEASUREMENT_ITERATIONS - 1],
        mean,
        std_dev,
        p50: latencies[MEASUREMENT_ITERATIONS / 2],
        p95: latencies[(MEASUREMENT_ITERATIONS * 95) / 100],
        p99: latencies[(MEASUREMENT_ITERATIONS * 99) / 100],
        router_cpu_time_ms,
    })
}

/// Benchmark concurrent throughput for a given transport
async fn benchmark_concurrent_throughput(
    transport: Transport,
    concurrency: usize,
) -> Result<ThroughputStats, Box<dyn std::error::Error>> {
    let payload = generate_test_payload();

    eprintln!("Starting servers for {} transport...", transport);

    // Start servers
    eprintln!("Spawning subgraph server...");
    let _subgraph = spawn_subgraph().await?;
    eprintln!("Subgraph server spawned");

    eprintln!("Spawning coprocessor server...");
    let (_coprocessor, socket_path) = match transport {
        Transport::Tcp => (spawn_tcp_coprocessor().await?, None),
        Transport::Uds => {
            let (guard, path) = spawn_uds_coprocessor().await?;
            (guard, Some(path))
        }
    };
    eprintln!("Coprocessor server spawned");

    // Give servers a moment to fully bind and start listening
    eprintln!("Waiting for servers to be ready...");
    tokio::time::sleep(Duration::from_millis(500)).await;

    eprintln!("Spawning router...");
    let _router = spawn_router(transport, socket_path.as_deref()).await?;
    let router_pid = _router.id().ok_or("Failed to get router PID")?;
    eprintln!("Router spawned with PID {} and ready", router_pid);

    // Warmup phase
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
    for _ in 0..WARMUP_ITERATIONS {
        execute_query(&client, &payload).await?;
    }

    // Get initial CPU time before measurement phase
    let cpu_start = get_cpu_time_ms(router_pid)?;

    // Measurement phase - collect latencies from all workers
    let completed = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut handles = Vec::with_capacity(concurrency);
    let start = Instant::now();

    for _ in 0..concurrency {
        let payload = payload.clone();
        let completed = completed.clone();
        let latencies = latencies.clone();

        handles.push(tokio::spawn(async move {
            let client =
                hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
            let mut local_latencies = Vec::new();

            loop {
                if start.elapsed() >= Duration::from_secs(CONCURRENT_DURATION_SECS) {
                    break;
                }

                let query_start = Instant::now();
                if execute_query(&client, &payload).await.is_ok() {
                    let latency = query_start.elapsed();
                    local_latencies.push(latency);
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Merge local latencies into shared vector
            let mut shared = latencies.lock().await;
            shared.extend(local_latencies);
        }));
    }

    for handle in handles {
        handle.await?;
    }

    let elapsed = start.elapsed();
    let total_requests = completed.load(Ordering::Relaxed);

    // Get final CPU time after measurement phase
    let cpu_end = get_cpu_time_ms(router_pid)?;
    let router_cpu_time_ms = cpu_end - cpu_start;

    // Calculate latency statistics
    let mut latencies = Arc::try_unwrap(latencies)
        .map_err(|_| "Failed to unwrap Arc")?
        .into_inner();
    latencies.sort();

    let (p50_latency, p95_latency, p99_latency, mean_latency) = if !latencies.is_empty() {
        let len = latencies.len();
        let p50 = latencies[len / 2];
        let p95 = latencies[(len * 95) / 100];
        let p99 = latencies[(len * 99) / 100];
        let sum: Duration = latencies.iter().sum();
        let mean = sum / len as u32;
        (p50, p95, p99, mean)
    } else {
        (Duration::ZERO, Duration::ZERO, Duration::ZERO, Duration::ZERO)
    };

    Ok(ThroughputStats {
        total_requests,
        elapsed,
        requests_per_sec: total_requests as f64 / elapsed.as_secs_f64(),
        router_cpu_time_ms,
        p50_latency,
        p95_latency,
        p99_latency,
        mean_latency,
    })
}

/// Spawn TCP-based coprocessor server
async fn spawn_tcp_coprocessor() -> Result<ShutdownOnDrop, Box<dyn std::error::Error>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(2);
    let shutdown_on_drop = ShutdownOnDrop(Some(tx));

    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    let addr: SocketAddr = format!("127.0.0.1:{}", TCP_COPROCESSOR_PORT).parse()?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    eprintln!(
        "TCP coprocessor server listening on port {}",
        TCP_COPROCESSOR_PORT
    );
    let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                conn = listener.accept() => {
                    let (stream, _peer) = conn.unwrap();
                    let stream = TokioIo::new(stream);
                    let conn = server.serve_connection_with_upgrades(
                        stream,
                        hyper::service::service_fn(coprocessor_handler)
                    );
                    let conn = graceful.watch(conn.into_owned());

                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                }
                _ = rx.recv() => {
                    drop(listener);
                    break;
                }
            }
        }

        tokio::select! {
            _ = graceful.shutdown() => {},
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    });

    Ok(shutdown_on_drop)
}

/// Spawn UDS-based coprocessor server
async fn spawn_uds_coprocessor() -> Result<(ShutdownOnDrop, PathBuf), Box<dyn std::error::Error>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(2);
    let shutdown_on_drop = ShutdownOnDrop(Some(tx));

    let temp_dir = tempfile::tempdir()?;
    let socket_path = temp_dir.path().join("coprocessor.sock");

    // Prevent temp_dir from being dropped (which would delete the directory)
    let _temp_dir_keep_alive = temp_dir.keep();

    // Remove socket file if it exists
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    eprintln!(
        "UDS coprocessor server listening on {}",
        socket_path.display()
    );
    let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();

    let socket_path_clone = socket_path.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                conn = listener.accept() => {
                    let (stream, _) = conn.unwrap();
                    let stream = TokioIo::new(stream);
                    let conn = server.serve_connection_with_upgrades(
                        stream,
                        hyper::service::service_fn(coprocessor_handler)
                    );
                    let conn = graceful.watch(conn.into_owned());

                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                }
                _ = rx.recv() => {
                    drop(listener);
                    break;
                }
            }
        }

        tokio::select! {
            _ = graceful.shutdown() => {},
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                eprintln!("UDS coprocessor graceful shutdown timeout");
            }
        }

        // Clean up socket file
        let _ = std::fs::remove_file(&socket_path_clone);
    });

    Ok((shutdown_on_drop, socket_path))
}

/// Coprocessor handler - processes coprocessor requests and returns control
async fn coprocessor_handler(
    req: http::Request<hyper::body::Incoming>,
) -> Result<http::Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    // Read body
    let bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            eprintln!("Coprocessor: Failed to read body: {}", e);
            return Ok(http::Response::builder()
                .status(500)
                .header(CONTENT_TYPE, "text/plain")
                .body(Full::new(Bytes::from(format!("Failed to read body: {}", e))))?);
        }
    };

    // Parse as JSON and set control to continue
    let mut payload: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Coprocessor: Failed to parse JSON: {}", e);
            // Return a minimal valid response
            json!({
                "version": 1,
                "stage": "RouterRequest",
                "control": "continue"
            })
        }
    };

    payload["control"] = json!("continue");

    let response_body = serde_json::to_vec(&payload)?;

    Ok(http::Response::builder()
        .status(200)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(response_body)))?)
}

/// Spawn mock subgraph server
async fn spawn_subgraph() -> Result<ShutdownOnDrop, Box<dyn std::error::Error>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(2);
    let shutdown_on_drop = ShutdownOnDrop(Some(tx));

    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    let addr: SocketAddr = format!("127.0.0.1:{}", SUBGRAPH_PORT).parse()?;
    socket.bind(addr)?;
    let listener = socket.listen(1024)?;
    eprintln!("Subgraph server listening on port {}", SUBGRAPH_PORT);
    let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                conn = listener.accept() => {
                    let (stream, _) = conn.unwrap();
                    let stream = TokioIo::new(stream);
                    let conn = server.serve_connection_with_upgrades(
                        stream,
                        hyper::service::service_fn(subgraph_handler)
                    );
                    let conn = graceful.watch(conn.into_owned());

                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            eprintln!("Subgraph connection error: {err}");
                        }
                    });
                }
                _ = rx.recv() => {
                    drop(listener);
                    break;
                }
            }
        }

        tokio::select! {
            _ = graceful.shutdown() => {},
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                eprintln!("Subgraph graceful shutdown timeout");
            }
        }
    });

    Ok(shutdown_on_drop)
}

/// Subgraph handler - returns mock GraphQL response
async fn subgraph_handler(
    req: http::Request<hyper::body::Incoming>,
) -> Result<http::Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    // Read and ignore request body
    let _ = req.into_body().collect().await?.to_bytes();

    let response = json!({
        "data": {
            "topProducts": [
                {"upc": "1", "name": "Table"}
            ]
        }
    });

    Ok(http::Response::builder()
        .status(200)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&response)?)))?)
}

/// Spawn router process with appropriate configuration
async fn spawn_router(
    transport: Transport,
    socket_path: Option<&Path>,
) -> Result<tokio::process::Child, Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bench_dir = manifest_dir
        .join("benches")
        .join("coprocessor_transport_benchmark");
    let schema_path = bench_dir.join("supergraph.graphql");

    let (config_path, _temp_config): (PathBuf, Option<()>) = match transport {
        Transport::Tcp => (bench_dir.join("router_h2c_tcp.yaml"), None),
        Transport::Uds => {
            // Create a config file with the actual socket path
            let config_template = std::fs::read_to_string(bench_dir.join("router_h2c_uds.yaml"))?;
            let socket_path_str = socket_path.unwrap().display().to_string();
            let config_content =
                config_template.replace("SOCKET_PATH_PLACEHOLDER", &socket_path_str);

            // Write to a non-temp file that we'll clean up manually
            let config_path = bench_dir.join("router_h2c_uds_runtime.yaml");
            std::fs::write(&config_path, &config_content)?;
            (config_path, None)
        }
    };

    let mut command = tokio::process::Command::new(ROUTER_EXE);
    command
        .args([
            "-s",
            schema_path.to_str().unwrap(),
            "-c",
            config_path.to_str().unwrap(),
            "--log",
            "error",
        ])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // Pass through enterprise credentials if available
    if let Ok(key) = std::env::var("TEST_APOLLO_KEY") {
        command.env("APOLLO_KEY", key);
    }
    if let Ok(graph_ref) = std::env::var("TEST_APOLLO_GRAPH_REF") {
        command.env("APOLLO_GRAPH_REF", graph_ref);
    }

    let mut child = command.spawn()?;

    // Take stdout and stderr before spawning tasks
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    // Consume stdout and stderr to prevent blocking
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(_)) = lines.next_line().await {}
    });
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(_)) = lines.next_line().await {}
    });

    // Wait for router to start (testing shows it takes ~2-3 seconds)
    tokio::time::sleep(Duration::from_secs(5)).await;

    Ok(child)
}

/// Generate test GraphQL payload (~1KB)
fn generate_test_payload() -> String {
    let base_query = r#"query BenchmarkQuery { topProducts { upc name } }"#;
    let base_size = base_query.len() + 50; // Account for JSON structure
    let target_size: usize = 1000;
    let padding = "_".repeat(target_size.saturating_sub(base_size));

    json!({
        "query": format!("{} # {}", base_query, padding),
        "variables": {}
    })
    .to_string()
}

/// Execute a GraphQL query against the router with a dozen custom headers
async fn execute_query(
    client: &hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    >,
    query: &str,
) -> Result<http::Response<hyper::body::Incoming>, Box<dyn std::error::Error>> {
    let request = http::Request::post(format!("http://127.0.0.1:{}", TCP_ROUTER_PORT))
        .header(CONTENT_TYPE, "application/json")
        .header("x-benchmark-header-1", "benchmark-value-1-abcdefghijklmnop")
        .header("x-benchmark-header-2", "benchmark-value-2-qrstuvwxyz123456")
        .header("x-benchmark-header-3", "benchmark-value-3-7890abcdefghijkl")
        .header("x-benchmark-header-4", "benchmark-value-4-mnopqrstuvwxyz12")
        .header("x-benchmark-header-5", "benchmark-value-5-3456789abcdefghi")
        .header("x-benchmark-header-6", "benchmark-value-6-jklmnopqrstuvwxy")
        .header("x-benchmark-header-7", "benchmark-value-7-z1234567890abcde")
        .header("x-benchmark-header-8", "benchmark-value-8-fghijklmnopqrstu")
        .header("x-benchmark-header-9", "benchmark-value-9-vwxyz1234567890a")
        .header("x-benchmark-header-10", "benchmark-value-10-bcdefghijklmnop")
        .header("x-benchmark-header-11", "benchmark-value-11-qrstuvwxyz12345")
        .header("x-benchmark-header-12", "benchmark-value-12-67890abcdefghij")
        .body(Full::new(Bytes::from(query.to_owned())))?;

    Ok(client.request(request).await?)
}

/// Print latency benchmark results
fn print_latency_results(tcp: &LatencyStats, uds: &LatencyStats) {
    println!("\n=================================================================");
    println!("Sequential Latency Benchmark Results");
    println!("=================================================================");
    println!(
        "Configuration: {} iterations, ~1KB payload, h2c\n",
        MEASUREMENT_ITERATIONS
    );

    println!(
        "{:<10} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>8} | {:>10}",
        "Transport", "Mean", "StdDev", "P50", "P95", "P99", "Min", "Max", "CPU(ms)"
    );
    println!(
        "{:-<10}-+-{:-<8}-+-{:-<8}-+-{:-<8}-+-{:-<8}-+-{:-<8}-+-{:-<8}-+-{:-<8}-+-{:-<10}",
        "", "", "", "", "", "", "", "", ""
    );

    print_latency_row("TCP", tcp);
    print_latency_row("UDS", uds);

    let latency_improvement =
        ((tcp.mean.as_secs_f64() - uds.mean.as_secs_f64()) / tcp.mean.as_secs_f64()) * 100.0;
    let cpu_improvement =
        ((tcp.router_cpu_time_ms - uds.router_cpu_time_ms) / tcp.router_cpu_time_ms) * 100.0;
    println!(
        "\nUDS Improvement: {:.1}% faster (mean latency), {:.1}% less CPU time",
        latency_improvement, cpu_improvement
    );
}

fn print_latency_row(label: &str, stats: &LatencyStats) {
    println!(
        "{:<10} | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>10.2}",
        label,
        stats.mean.as_secs_f64() * 1000.0,
        stats.std_dev.as_secs_f64() * 1000.0,
        stats.p50.as_secs_f64() * 1000.0,
        stats.p95.as_secs_f64() * 1000.0,
        stats.p99.as_secs_f64() * 1000.0,
        stats.min.as_secs_f64() * 1000.0,
        stats.max.as_secs_f64() * 1000.0,
        stats.router_cpu_time_ms,
    );
}

/// Print throughput benchmark results
fn print_throughput_results(
    tcp_results: &[(usize, ThroughputStats)],
    uds_results: &[(usize, ThroughputStats)],
) {
    println!("\n=================================================================");
    println!("Concurrent Throughput Benchmark Results");
    println!("=================================================================");
    println!(
        "Configuration: {}s per test, ~1KB payload, h2c\n",
        CONCURRENT_DURATION_SECS
    );

    println!(
        "{:<10} | {:>11} | {:>10} | {:>10} | {:>8} | {:>8} | {:>8} | {:>10} | {:>11}",
        "Transport", "Concurrency", "Requests", "Req/sec", "P50", "P95", "P99", "CPU(ms)", "Improvement"
    );
    println!(
        "{:-<10}-+-{:-<11}-+-{:-<10}-+-{:-<10}-+-{:-<8}-+-{:-<8}-+-{:-<8}-+-{:-<10}-+-{:-<11}",
        "", "", "", "", "", "", "", "", ""
    );

    for i in 0..tcp_results.len() {
        let (tcp_conc, tcp_stats) = &tcp_results[i];
        let (_, uds_stats) = &uds_results[i];

        let throughput_improvement = ((uds_stats.requests_per_sec - tcp_stats.requests_per_sec)
            / tcp_stats.requests_per_sec)
            * 100.0;

        println!(
            "{:<10} | {:>11} | {:>10} | {:>10.2} | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>10.2} | {:>10}",
            "TCP",
            tcp_conc,
            format_number(tcp_stats.total_requests),
            tcp_stats.requests_per_sec,
            tcp_stats.p50_latency.as_secs_f64() * 1000.0,
            tcp_stats.p95_latency.as_secs_f64() * 1000.0,
            tcp_stats.p99_latency.as_secs_f64() * 1000.0,
            tcp_stats.router_cpu_time_ms,
            "-"
        );

        let cpu_improvement = ((tcp_stats.router_cpu_time_ms - uds_stats.router_cpu_time_ms)
            / tcp_stats.router_cpu_time_ms)
            * 100.0;

        let p95_improvement = ((tcp_stats.p95_latency.as_secs_f64() - uds_stats.p95_latency.as_secs_f64())
            / tcp_stats.p95_latency.as_secs_f64())
            * 100.0;

        println!(
            "{:<10} | {:>11} | {:>10} | {:>10.2} | {:>7.2}ms | {:>7.2}ms | {:>7.2}ms | {:>10.2} | {:>+10.1}%",
            "UDS",
            tcp_conc,
            format_number(uds_stats.total_requests),
            uds_stats.requests_per_sec,
            uds_stats.p50_latency.as_secs_f64() * 1000.0,
            uds_stats.p95_latency.as_secs_f64() * 1000.0,
            uds_stats.p99_latency.as_secs_f64() * 1000.0,
            uds_stats.router_cpu_time_ms,
            throughput_improvement
        );

        println!(
            "{:<10}   {:>11}   {:>10}   {:>10}   {:>8}   P95: {:>+5.1}%   {:>8}   CPU: {:>+7.1}%",
            "", "", "", "", "", p95_improvement, "", cpu_improvement
        );
    }
}

/// Print CSV output for further analysis
fn print_csv_output(
    tcp_latency: &LatencyStats,
    uds_latency: &LatencyStats,
    tcp_throughput: &[(usize, ThroughputStats)],
    uds_throughput: &[(usize, ThroughputStats)],
) {
    println!("\n=================================================================");
    println!("CSV Output");
    println!("=================================================================");

    println!("\n# Sequential Latency");
    println!(
        "test_type,transport,payload_size,iterations,min_us,max_us,mean_us,std_dev_us,p50_us,p95_us,p99_us,router_cpu_ms"
    );

    println!(
        "sequential,TCP,1000,{},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.2}",
        MEASUREMENT_ITERATIONS,
        tcp_latency.min.as_micros(),
        tcp_latency.max.as_micros(),
        tcp_latency.mean.as_micros(),
        tcp_latency.std_dev.as_micros(),
        tcp_latency.p50.as_micros(),
        tcp_latency.p95.as_micros(),
        tcp_latency.p99.as_micros(),
        tcp_latency.router_cpu_time_ms,
    );

    println!(
        "sequential,UDS,1000,{},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.0},{:.2}",
        MEASUREMENT_ITERATIONS,
        uds_latency.min.as_micros(),
        uds_latency.max.as_micros(),
        uds_latency.mean.as_micros(),
        uds_latency.std_dev.as_micros(),
        uds_latency.p50.as_micros(),
        uds_latency.p95.as_micros(),
        uds_latency.p99.as_micros(),
        uds_latency.router_cpu_time_ms,
    );

    println!("\n# Concurrent Throughput");
    println!(
        "test_type,transport,payload_size,concurrency,duration_secs,total_requests,requests_per_sec,p50_us,p95_us,p99_us,mean_us,router_cpu_ms"
    );

    for (concurrency, stats) in tcp_throughput {
        println!(
            "concurrent,TCP,1000,{},{},{},{:.2},{:.0},{:.0},{:.0},{:.0},{:.2}",
            concurrency,
            CONCURRENT_DURATION_SECS,
            stats.total_requests,
            stats.requests_per_sec,
            stats.p50_latency.as_micros(),
            stats.p95_latency.as_micros(),
            stats.p99_latency.as_micros(),
            stats.mean_latency.as_micros(),
            stats.router_cpu_time_ms
        );
    }

    for (concurrency, stats) in uds_throughput {
        println!(
            "concurrent,UDS,1000,{},{},{},{:.2},{:.0},{:.0},{:.0},{:.0},{:.2}",
            concurrency,
            CONCURRENT_DURATION_SECS,
            stats.total_requests,
            stats.requests_per_sec,
            stats.p50_latency.as_micros(),
            stats.p95_latency.as_micros(),
            stats.p99_latency.as_micros(),
            stats.mean_latency.as_micros(),
            stats.router_cpu_time_ms
        );
    }
}

/// Format large numbers with commas
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}
