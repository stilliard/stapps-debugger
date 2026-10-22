//! Checking if an IP may send email for a domain, using mail-auth's SPF evaluator.

use std::net::IpAddr;

use mail_auth::MessageAuthenticator;
use mail_auth::hickory_resolver::proto::rr::{Name, RData};
use mail_auth::spf::verify::SpfParameters;

pub struct SpfCheck {
    /// PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR or PERMERROR
    pub status: String,
    /// The domain's SPF records (there should only be one)
    pub records: Vec<String>,
    /// The record with the IP added, when that would fix it
    pub suggestion: Option<String>,
}

/// Check if `ip` may send email from `email`, an address at `domain`
pub async fn check(dns: &MessageAuthenticator, ip: IpAddr, domain: &str, email: &str) -> SpfCheck {
    let params = SpfParameters::verify_mail_from(ip, domain, domain, email);
    let status = dns
        .verify_spf(params)
        .await
        .result()
        .to_string()
        .to_uppercase();
    let records = records(dns, domain).await;

    let suggestion =
        if records.len() == 1 && ["FAIL", "SOFTFAIL", "NEUTRAL"].contains(&status.as_str()) {
            Some(with_ip(&records[0], ip))
        } else {
            None
        };

    SpfCheck {
        status,
        records,
        suggestion,
    }
}

/// The domain's SPF records, to show alongside the result
async fn records(dns: &MessageAuthenticator, domain: &str) -> Vec<String> {
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

/// The SPF record with the IP allowed first, e.g. "v=spf1 ip4:1.2.3.4 include:… ~all"
fn with_ip(record: &str, ip: IpAddr) -> String {
    let mechanism = if ip.is_ipv4() { "ip4" } else { "ip6" };
    // records() only returns records starting with "v=spf1", in any case
    let rest = &record["v=spf1".len()..];
    format!("v=spf1 {mechanism}:{ip}{rest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_add_the_ip_whatever_the_case_of_the_record() {
        let ipv4 = "1.2.3.4".parse().unwrap();
        let ipv6 = "2001:db8::1".parse().unwrap();

        assert_eq!(
            with_ip("v=spf1 include:_spf.example.com ~all", ipv4),
            "v=spf1 ip4:1.2.3.4 include:_spf.example.com ~all"
        );
        assert_eq!(with_ip("V=SPF1 -all", ipv4), "v=spf1 ip4:1.2.3.4 -all");
        assert_eq!(with_ip("v=spf1", ipv6), "v=spf1 ip6:2001:db8::1");
    }

    /// Looks up real DNS, so it's skipped by default: `cargo test -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn real_domains_give_the_same_results_as_the_old_php_version() {
        let dns = MessageAuthenticator::new_system_conf().unwrap();
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

        for (domain, ip, status) in expected {
            let email = format!("test@{domain}");
            let result = check(&dns, ip.parse().unwrap(), domain, &email).await;

            assert_eq!(result.status, status, "{domain} {ip}");
        }
    }
}
