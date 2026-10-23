//! The pages, rendered from the askama templates in templates/.

use std::collections::HashMap;

use askama::Template;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use crate::spf::SpfCheck;

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexPage {
    pub title: &'static str,
}

#[derive(Template, Default)]
#[template(path = "spf.html")]
pub struct SpfPage {
    pub title: &'static str,
    pub ip: String,
    pub email: String,
    pub domain: String,
    pub invalid_ip: bool,
    pub check: Option<SpfCheck>,
}

impl SpfPage {
    /// The SPF page with the form filled in from the request
    pub fn new(params: &HashMap<String, String>) -> Self {
        let param = |name| {
            params
                .get(name)
                .map_or("", |value| value.trim())
                .to_string()
        };
        let email = param("email");

        Self {
            title: "SPF Debugger",
            ip: param("ip"),
            domain: email.rsplit('@').next().unwrap_or_default().to_lowercase(),
            email,
            ..Default::default()
        }
    }
}

pub fn render(page: impl Template) -> Response {
    match page.render() {
        Ok(html) => Html(html).into_response(),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response(),
    }
}
