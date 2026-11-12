//! Looks up known vulnerabilities for detected components in the NVD (API 2.0).
//!
//! This is the only part of ifscan that touches the network, and it sends nothing
//! but CPE names such as `cpe:2.3:a:openssl:openssl:3.0.13:...`.
use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::Value;
use std::{thread::sleep, time::Duration};

const ENDPOINT: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Vuln { pub id: String, pub severity: String, pub score: Option<f64>, pub published: String, pub summary: String }

/// Extracts the fields ifscan reports from an NVD response body.
pub fn parse_response(body: &Value) -> Vec<Vuln> {
    let mut out: Vec<Vuln> = body["vulnerabilities"].as_array().into_iter().flatten().filter_map(|v| {
        let c = &v["cve"];
        let id = c["id"].as_str()?.to_string();
        // Prefer the newest scoring scheme the record carries.
        let metric = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"].iter()
            .find_map(|k| c["metrics"][k].as_array().and_then(|a| a.first()));
        let score = metric.and_then(|m| m["cvssData"]["baseScore"].as_f64());
        let severity = metric.and_then(|m| m["cvssData"]["baseSeverity"].as_str().or(m["baseSeverity"].as_str()))
            .unwrap_or("UNKNOWN").to_lowercase();
        let summary = c["descriptions"].as_array().into_iter().flatten()
            .find(|d| d["lang"] == "en").and_then(|d| d["value"].as_str()).unwrap_or("")
            .split_whitespace().collect::<Vec<_>>().join(" ");
        Some(Vuln { id, severity, score, published: c["published"].as_str().unwrap_or("").chars().take(10).collect(), summary })
    }).collect();
    out.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal).then(a.id.cmp(&b.id)));
    out
}

/// Queries the NVD for one CPE name. `api_key` raises the rate limit but is optional.
pub fn lookup(cpe: &str, api_key: Option<&str>) -> Result<Vec<Vuln>> {
    let mut out = Vec::new();
    let mut start = 0u64;
    loop {
        let mut last = None;
        let mut body = None;
        for attempt in 0..4 {
            let mut req = ureq::get(ENDPOINT).query("cpeName", cpe).query("startIndex", &start.to_string())
                .timeout(Duration::from_secs(40));
            if let Some(k) = api_key { req = req.set("apiKey", k); }
            match req.call() {
                Ok(r) => { body = Some(r.into_json::<Value>()?); break; }
                // Without a key the NVD allows 5 requests per 30 seconds and answers 403/429/503 beyond that.
                Err(ureq::Error::Status(code, _)) if matches!(code, 403 | 429 | 503) => { last = Some(anyhow!("NVD answered HTTP {code}")); sleep(Duration::from_secs(8 * (attempt + 1))); }
                Err(e) => return Err(anyhow!("NVD request failed: {e}")),
            }
        }
        let body = body.ok_or_else(|| last.unwrap_or_else(|| anyhow!("NVD request failed")))?;
        out.extend(parse_response(&body));
        let total = body["totalResults"].as_u64().unwrap_or(0);
        let got = body["resultsPerPage"].as_u64().unwrap_or(0);
        start += got;
        if got == 0 || start >= total { break; }
        sleep(Duration::from_secs(if api_key.is_some() { 1 } else { 6 }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_nvd_records() {
        let body = serde_json::json!({"totalResults": 2, "resultsPerPage": 2, "vulnerabilities": [
            {"cve": {"id": "CVE-2024-0001", "published": "2024-02-01T10:00:00.000", "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Low  one\n here"}],
                     "metrics": {"cvssMetricV2": [{"baseSeverity": "LOW", "cvssData": {"baseScore": 2.1}}]}}},
            {"cve": {"id": "CVE-2024-0002", "published": "2024-03-01T10:00:00.000", "descriptions": [{"lang": "en", "value": "Bad one"}],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}], "cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]}}}]});
        let v = parse_response(&body);
        assert_eq!(v[0], Vuln { id: "CVE-2024-0002".into(), severity: "critical".into(), score: Some(9.8), published: "2024-03-01".into(), summary: "Bad one".into() });
        assert_eq!((v[1].severity.as_str(), v[1].summary.as_str()), ("low", "Low one here"));
        assert!(parse_response(&serde_json::json!({})).is_empty());
    }
}
