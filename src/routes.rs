//! The URLs and what each one does.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
use axum::middleware::map_response;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use mail_auth::MessageAuthenticator;

use crate::pages::{IndexPage, SpfPage, render};
use crate::{security_headers, spf};

/// What the handlers share
pub struct AppState {
    pub dns: MessageAuthenticator,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            // the system resolver, as hickory fails on large responses (like github.com's
            // TXT records) when given a public resolver directly
            dns: MessageAuthenticator::new_system_conf().expect("could not set up DNS"),
        }
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/spf", get(spf_form).post(spf_check))
        .route("/app.css", get(css))
        .fallback(|| async { (StatusCode::NOT_FOUND, "Not found") })
        .layer(map_response(security_headers::add))
        .with_state(state)
}

async fn index() -> Response {
    render(IndexPage { title: "Debugger" })
}

/// The SPF form, which links can prefill, e.g. /spf?ip=1.2.3.4&email=info@example.com
async fn spf_form(Query(params): Query<HashMap<String, String>>) -> Response {
    render(SpfPage::new(&params))
}

/// Check if an email address can send from an IP. Checks are POSTed, so the
/// addresses stay out of URLs, browser history and access logs.
async fn spf_check(
    State(state): State<Arc<AppState>>,
    Form(params): Form<HashMap<String, String>>,
) -> Response {
    let mut page = SpfPage::new(&params);

    if page.ip.is_empty() || page.domain.is_empty() {
        return render(page);
    }
    let Ok(ip) = page.ip.parse::<IpAddr>() else {
        page.invalid_ip = true;
        return render(page);
    };

    page.check = Some(spf::check(&state.dns, ip, &page.domain, &page.email).await);
    render(page)
}

async fn css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../public/app.css"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    async fn get(url: &str) -> (StatusCode, String) {
        send(Request::builder().uri(url).body(Body::empty()).unwrap()).await
    }

    async fn post(url: &str, form: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method("POST")
            .uri(url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form.to_string()))
            .unwrap();
        send(request).await
    }

    async fn send(request: Request<Body>) -> (StatusCode, String) {
        let response = app(Arc::new(AppState::new()))
            .oneshot(request)
            .await
            .unwrap();
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
    async fn links_prefill_the_form_without_checking() {
        let (status, page) = get("/spf?ip=1.2.3.4&email=a@example.com").await;

        assert_eq!(status, StatusCode::OK);
        assert!(page.contains(r#"value="1.2.3.4""#));
        assert!(page.contains(r#"value="a@example.com""#));
        assert!(!page.contains("SPF Validation Results"));
    }

    #[tokio::test]
    async fn invalid_ips_are_reported() {
        let (_, page) = post("/spf", "ip=nope&email=a@example.com").await;
        assert!(page.contains("\"nope\" doesn't look like an IP address."));
    }

    #[tokio::test]
    async fn a_missing_email_just_shows_the_form() {
        let (_, page) = post("/spf", "ip=1.2.3.4").await;
        assert!(!page.contains("look like an IP address"));
        assert!(page.contains("Let's check if an email address can send from a given IP."));
    }

    #[tokio::test]
    async fn input_is_escaped() {
        let (_, prefilled) = get("/spf?ip=%22%3E%3Cscript%3E&email=a@example.com").await;
        let (_, checked) = post("/spf", "ip=%22%3E%3Cscript%3E&email=a@example.com").await;

        assert!(!prefilled.contains("<script>"));
        assert!(!checked.contains("<script>"));
    }

    #[tokio::test]
    async fn security_headers_are_added() {
        let response = app(Arc::new(AppState::new()))
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
    }
}
