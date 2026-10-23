//! A place for quickly debugging common issues. This starts the server; the URLs
//! are in routes.rs.

mod pages;
mod rate_limit;
mod routes;
mod security_headers;
mod spf;

use std::sync::Arc;

use routes::AppState;
use tokio::signal::unix::{SignalKind, signal};

// one thread is plenty here, and uses far less CPU than tokio's default of one per core
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let address = format!("0.0.0.0:{port}");

    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("could not listen on that port");
    println!("listening on http://{address}");

    axum::serve(listener, routes::app(Arc::new(AppState::new())))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

/// Wait for Ctrl+C or SIGTERM (`docker stop`). In Docker we're the only process,
/// so without this SIGTERM is ignored until Docker kills us.
async fn shutdown_signal() {
    let mut terminate = signal(SignalKind::terminate()).expect("could not listen for SIGTERM");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}
