//! Limiting how many SPF checks each visitor can run, so bots can't use the
//! debugger for lots of DNS lookups.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

/// A real user won't need more than this
const CHECKS_PER_HOUR: usize = 20;
const HOUR: Duration = Duration::from_secs(60 * 60);

/// When each visitor ran their checks in the last hour
#[derive(Default)]
pub struct RateLimiter(Mutex<HashMap<IpAddr, Vec<Instant>>>);

impl RateLimiter {
    /// Count a check for the visitor making this request, or false if they've
    /// already run CHECKS_PER_HOUR in the last hour
    pub fn allow(&self, headers: &HeaderMap) -> bool {
        // Dokku's nginx on Ba1 sets X-Forwarded-For to the visitor's IP (trusting
        // Cloudflare's CF-Connecting-IP), and the app is only reachable through it.
        // Locally there's no header, so no limit.
        let Some(visitor) = visitor_ip(headers) else {
            return true;
        };

        let mut checks = self.0.lock().unwrap();

        // forget checks from over an hour ago, and visitors with none left
        checks.retain(|_, times| {
            times.retain(|time| time.elapsed() < HOUR);
            !times.is_empty()
        });

        let times = checks.entry(visitor).or_default();
        if times.len() >= CHECKS_PER_HOUR {
            return false;
        }
        times.push(Instant::now());
        true
    }
}

/// The last IP in X-Forwarded-For, the one our nginx added. Dokku replaces the
/// header rather than appending to it, but this works either way.
fn visitor_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let forwarded_for = headers.get("x-forwarded-for")?.to_str().ok()?;
    forwarded_for.rsplit(',').next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from(ip: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", ip.parse().unwrap());
        headers
    }

    #[test]
    fn each_visitor_gets_their_own_checks_per_hour() {
        let limiter = RateLimiter::default();

        for _ in 0..CHECKS_PER_HOUR {
            assert!(limiter.allow(&from("192.0.2.1")));
        }
        assert!(!limiter.allow(&from("192.0.2.1")));
        assert!(limiter.allow(&from("192.0.2.2")));
    }

    #[test]
    fn the_visitor_is_the_last_forwarded_ip() {
        assert_eq!(visitor_ip(&from("192.0.2.1")), "192.0.2.1".parse().ok());
        assert_eq!(
            visitor_ip(&from("203.0.113.9, 192.0.2.1")),
            "192.0.2.1".parse().ok()
        );
        assert_eq!(visitor_ip(&from("not an ip")), None);
    }

    #[test]
    fn there_is_no_limit_without_a_visitor_ip() {
        let limiter = RateLimiter::default();

        for _ in 0..CHECKS_PER_HOUR * 2 {
            assert!(limiter.allow(&HeaderMap::new()));
        }
    }
}
