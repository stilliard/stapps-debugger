//! The debugger's pages, with the SPF check done by mail-auth's SPF evaluator.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use askama::Template;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::map_response;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use mail_auth::MessageAuthenticator;
use mail_auth::hickory_resolver::proto::rr::{Name, RData};
use mail_auth::spf::verify::SpfParameters;
use tokio::signal::unix::{SignalKind, signal};

type Dns = Arc<MessageAuthenticator>;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexPage {
    title: &'static str,
}

#[derive(Template, Default)]
#[template(path = "spf.html")]
struct SpfPage {
    title: &'static str,
    ip: String,
    email: String,
    domain: String,
    invalid_ip: bool,
    status: Option<String>,
    records: Vec<String>,
    suggestion: Option<String>,
}

// one thread is plenty here, and uses far less CPU than tokio's default of one per core
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let address = format!("0.0.0.0:{port}");
    // the system resolver, as hickory fails on large responses (like github.com's TXT records)
    // when given a public resolver directly
    let dns = MessageAuthenticator::new_system_conf().expect("could not set up DNS");

    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("could not listen on that port");
    println!("listening on http://{address}");

    axum::serve(listener, app(Arc::new(dns)))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

fn app(dns: Dns) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async { render(IndexPage { title: "Debugger" }) }),
        )
        .route("/spf", get(spf))
        .route("/app.css", get(css))
        .fallback(|| async { (StatusCode::NOT_FOUND, "Not found") })
        .layer(map_response(security_headers))
        .with_state(dns)
}

/// Check if an email address can send from an IP, e.g. /spf?ip=1.2.3.4&email=info@example.com
async fn spf(State(dns): State<Dns>, Query(params): Query<HashMap<String, String>>) -> Response {
    let param = |name| {
        params
            .get(name)
            .map_or("", |value| value.trim())
            .to_string()
    };
    let email = param("email");
    let mut page = SpfPage {
        title: "SPF Debugger",
        ip: param("ip"),
        domain: email.rsplit('@').next().unwrap_or_default().to_lowercase(),
        email,
        ..Default::default()
    };

    if page.ip.is_empty() || page.domain.is_empty() {
        return render(page);
    }
    let Ok(ip) = page.ip.parse::<IpAddr>() else {
        page.invalid_ip = true;
        return render(page);
    };

    let params = SpfParameters::verify_mail_from(ip, &page.domain, &page.domain, &page.email);
    let status = dns
        .verify_spf(params)
        .await
        .result()
        .to_string()
        .to_uppercase();
    page.records = spf_records(&dns, &page.domain).await;

    // suggest adding the IP when that would fix it
    if page.records.len() == 1 && ["FAIL", "SOFTFAIL", "NEUTRAL"].contains(&status.as_str()) {
        let mechanism = if ip.is_ipv4() { "ip4" } else { "ip6" };
        page.suggestion =
            Some(page.records[0].replacen("v=spf1", &format!("v=spf1 {mechanism}:{ip}"), 1));
    }

    page.status = Some(status);
    render(page)
}

/// The domain's SPF records, to show alongside the result
async fn spf_records(dns: &MessageAuthenticator, domain: &str) -> Vec<String> {
    let Ok(name) = Name::from_str_relaxed(format!("{domain}.")) else {
        return vec![];
    };
    let Ok(lookup) = dns.resolver().txt_lookup(name).await else {
        return vec![];
    };

    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|part| String::from_utf8_lossy(part))
                    .collect::<String>(),
            ),
            _ => None,
        })
        .filter(|txt| {
            txt.eq_ignore_ascii_case("v=spf1") || txt.to_ascii_lowercase().starts_with("v=spf1 ")
        })
        .collect()
}

async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../public/app.css"),
    )
}

fn render(page: impl Template) -> Response {
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}

async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    response
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    async fn get(url: &str) -> (StatusCode, String) {
        let dns = MessageAuthenticator::new_system_conf().unwrap();
        let request = Request::builder().uri(url).body(Body::empty()).unwrap();
        let response = app(Arc::new(dns)).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn pages_are_served() {
        let (status, home) = get("/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(home.contains("<title>Debugger</title>"));

        let (status, spf) = get("/spf").await;
        assert_eq!(status, StatusCode::OK);
        assert!(spf.contains("<title>SPF Debugger</title>"));
        assert!(spf.contains("Let's check if an email address can send from a given IP."));

        let (status, _) = get("/app.css").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn anything_else_is_not_found() {
        let (status, _) = get("/spf.html").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn invalid_ips_are_reported() {
        let (_, page) = get("/spf?ip=nope&email=a@example.com").await;
        assert!(page.contains("\"nope\" doesn't look like an IP address."));
    }

    #[tokio::test]
    async fn input_is_escaped() {
        let (_, page) = get("/spf?ip=%22%3E%3Cscript%3E&email=a@example.com").await;
        assert!(!page.contains("<script>"));
    }

    /// Looks up real DNS, so it's skipped by default: `cargo test -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn real_domains_give_the_same_results_as_the_old_php_version() {
        let expected = [
            ("gmail.com", "209.85.220.41", "PASS"),
            ("gmail.com", "1.2.3.4", "SOFTFAIL"),
            ("gmail.com", "2607:f8b0:4864:20::1", "PASS"),
            ("missionresources.co.uk", "5.153.230.21", "FAIL"),
            ("example.com", "1.2.3.4", "FAIL"),
            ("no-spf-here-zz91x.com", "1.2.3.4", "NONE"),
            ("outlook.com", "40.92.0.1", "PASS"),
            ("github.com", "192.30.252.1", "PASS"),
            ("salesforce.com", "1.2.3.4", "SOFTFAIL"),
            ("mailgun.org", "1.2.3.4", "FAIL"),
            ("amazon.com", "1.2.3.4", "FAIL"),
            ("stapps.io", "1.2.3.4", "SOFTFAIL"),
        ];

        for (domain, ip, result) in expected {
            let (_, page) = get(&format!("/spf?ip={ip}&email=test@{domain}")).await;
            let found = match () {
                _ if page.contains("All good!") => "PASS",
                _ if page.contains("No SPF record setup") => "NONE",
                _ => page
                    .split("<strong>")
                    .nth(1)
                    .unwrap()
                    .split("</strong>")
                    .next()
                    .unwrap(),
            };
            assert_eq!(found, result, "{domain} {ip}");
        }
    }
}
