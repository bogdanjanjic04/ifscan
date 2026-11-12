//! Finds third-party components embedded in binaries by their version banners.
//!
//! QNX images carry no package database, so the banner a library compiles into
//! itself is the most reliable evidence of what version actually shipped.
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Detected { pub name: &'static str, pub version: String, pub cpe: String }

struct Sig { name: &'static str, vendor: &'static str, product: &'static str, marker: &'static [u8] }

const SIGS: &[Sig] = &[
    Sig { name: "OpenSSL", vendor: "openssl", product: "openssl", marker: b"OpenSSL " },
    Sig { name: "zlib", vendor: "zlib", product: "zlib", marker: b" deflate " },
    Sig { name: "zlib", vendor: "zlib", product: "zlib", marker: b" inflate " },
    Sig { name: "curl", vendor: "haxx", product: "libcurl", marker: b"libcurl/" },
    Sig { name: "BusyBox", vendor: "busybox", product: "busybox", marker: b"BusyBox v" },
    Sig { name: "libpng", vendor: "libpng", product: "libpng", marker: b"libpng version " },
    Sig { name: "Expat", vendor: "libexpat_project", product: "libexpat", marker: b"expat_" },
    Sig { name: "OpenSSH", vendor: "openbsd", product: "openssh", marker: b"OpenSSH_" },
    Sig { name: "Dropbear", vendor: "dropbear_ssh_project", product: "dropbear_ssh", marker: b"SSH-2.0-dropbear_" },
    Sig { name: "SQLite", vendor: "sqlite", product: "sqlite", marker: b"SQLite version " },
    Sig { name: "libxml2", vendor: "xmlsoft", product: "libxml2", marker: b"libxml2-" },
    Sig { name: "mbed TLS", vendor: "arm", product: "mbed_tls", marker: b"mbed TLS " },
    Sig { name: "wolfSSL", vendor: "wolfssl", product: "wolfssl", marker: b"wolfSSL " },
    Sig { name: "lighttpd", vendor: "lighttpd", product: "lighttpd", marker: b"lighttpd/" },
    Sig { name: "dnsmasq", vendor: "thekelleys", product: "dnsmasq", marker: b"dnsmasq-" },
];

fn version_at(b: &[u8]) -> Option<String> {
    let n = b.iter().take(24).position(|c| !(c.is_ascii_alphanumeric() || *c == b'.')).unwrap_or(b.len().min(24));
    let v = std::str::from_utf8(&b[..n]).ok()?.trim_end_matches('.');
    let mut parts = v.split('.');
    let major = parts.next()?;
    // need at least major.minor, each starting with a digit; rejects words like "OpenSSL error"
    let minor = parts.next()?;
    if major.is_empty() || !major.bytes().all(|c| c.is_ascii_digit()) || major.len() > 4 { return None; }
    if !minor.bytes().next()?.is_ascii_digit() { return None; }
    Some(v.to_string())
}

pub fn detect(data: &[u8]) -> Vec<Detected> {
    let mut out = Vec::new();
    for s in SIGS {
        for p in memchr::memmem::find_iter(data, s.marker) {
            let at = p + s.marker.len();
            if let Some(version) = version_at(&data[at..]) {
                let d = Detected { name: s.name, cpe: format!("cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*", s.vendor, s.product, version), version };
                if !out.contains(&d) { out.push(d); }
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_banners_and_ignores_prose() {
        let blob = b"\0\0OpenSSL 3.0.13 30 Jan 2024\0OpenSSL error\0 deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly\0BusyBox v1.36.1 (2024)\0libcurl/8.5.0\0";
        let d = detect(blob);
        let got: Vec<(&str, &str)> = d.iter().map(|x| (x.name, x.version.as_str())).collect();
        assert_eq!(got, vec![("BusyBox", "1.36.1"), ("OpenSSL", "3.0.13"), ("curl", "8.5.0"), ("zlib", "1.2.11")]);
        assert_eq!(d[1].cpe, "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*");
        assert!(detect(b"OpenSSL is a toolkit; version x.y").is_empty());
    }
}
