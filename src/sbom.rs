//! Report assembly: per-file facts, dependency resolution and CycloneDX output.
use crate::{elfinfo::{self, ElfInfo}, ifs::{EntryKind, Image}, versions::{self, Detected}};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct Component { pub path: String, pub size: u32, pub sha256: String, pub mode: String, pub setuid: bool, pub elf: Option<ElfInfo>, pub embedded: Vec<Detected> }

#[derive(Debug, Serialize)]
pub struct Finding { pub severity: &'static str, pub rule: &'static str, pub path: String, pub detail: String }

#[derive(Debug, Serialize)]
pub struct Report { pub image: Image, pub components: Vec<Component>, pub findings: Vec<Finding>, pub unresolved: BTreeMap<String, Vec<String>> }

pub fn build(img: Image, data: &[u8]) -> Report {
    let mut components = Vec::new();
    let mut findings = Vec::new();
    for e in &img.entries {
        let EntryKind::File { size, .. } = e.kind else { continue };
        let Some(bytes) = img.file_data(data, e) else {
            findings.push(Finding { severity: "high", rule: "truncated-file", path: e.path.clone(), detail: "file data lies outside the image".into() });
            continue;
        };
        let elf = elfinfo::inspect(bytes);
        let setuid = e.mode & 0o6000 != 0;
        if e.mode & 0o002 != 0 { findings.push(Finding { severity: "low", rule: "world-writable", path: e.path.clone(), detail: format!("mode {:o}; harmless while it stays in the read-only image, a problem once copied to a writable filesystem", e.mode & 0o7777) }); }
        if setuid { findings.push(Finding { severity: "medium", rule: "setuid", path: e.path.clone(), detail: format!("mode {:o}, owner uid {}", e.mode & 0o7777, e.uid) }); }
        if let Some(i) = &elf {
            let h = &i.hardening;
            if i.kind == "executable" && !h.pie { findings.push(Finding { severity: "medium", rule: "no-pie", path: e.path.clone(), detail: "fixed load address; ASLR cannot relocate it".into() }); }
            if h.nx_stack == Some(false) { findings.push(Finding { severity: "high", rule: "exec-stack", path: e.path.clone(), detail: "PT_GNU_STACK asks for an executable stack".into() }); }
            if !h.relro && i.kind != "object" { findings.push(Finding { severity: "low", rule: "no-relro", path: e.path.clone(), detail: "GOT stays writable after startup".into() }); }
            if setuid && !h.stack_protector { findings.push(Finding { severity: "medium", rule: "setuid-no-canary", path: e.path.clone(), detail: "privileged binary without stack protector".into() }); }
        }
        components.push(Component { path: e.path.clone(), size, sha256: hex(&Sha256::digest(bytes)), mode: format!("{:o}", e.mode & 0o7777), setuid, elf, embedded: versions::detect(bytes) });
    }
    // Resolve DT_NEEDED against sonames and file names present in the image.
    let mut provided: BTreeSet<String> = BTreeSet::new();
    for e in &img.entries { if let Some(n) = e.path.rsplit('/').next() { provided.insert(n.to_string()); } }
    for c in &components { if let Some(s) = c.elf.as_ref().and_then(|i| i.soname.clone()) { provided.insert(s); } }
    let mut unresolved: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for c in &components { if let Some(i) = &c.elf { for n in &i.needed { if !provided.contains(n) { unresolved.entry(n.clone()).or_default().push(c.path.clone()); } } } }
    for (lib, users) in &unresolved {
        findings.push(Finding { severity: "info", rule: "unresolved-library", path: users[0].clone(), detail: format!("{lib} is needed by {} file(s) but is not in this image", users.len()) });
    }
    Report { image: img, components, findings, unresolved }
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

pub fn cyclonedx(r: &Report, source: &str) -> Value {
    let comps: Vec<Value> = r.components.iter().map(|c| {
        let ty = match c.elf.as_ref().map(|e| e.kind.as_str()) { Some("shared-library") => "library", Some("executable") => "application", _ => "file" };
        let mut props = vec![json!({"name": "qnx:ifs:mode", "value": c.mode})];
        if let Some(e) = &c.elf {
            props.push(json!({"name": "elf:arch", "value": e.arch}));
            if let Some(b) = &e.build_id { props.push(json!({"name": "elf:build-id", "value": b})); }
            if let Some(s) = &e.soname { props.push(json!({"name": "elf:soname", "value": s})); }
            props.push(json!({"name": "elf:hardening", "value": serde_json::to_string(&e.hardening).unwrap()}));
        }
        json!({"type": ty, "bom-ref": c.path, "name": c.path.rsplit('/').next().unwrap_or(&c.path),
               "hashes": [{"alg": "SHA-256", "content": c.sha256}], "properties": props})
    }).collect();
    let mut comps = comps;
    let mut seen = BTreeSet::new();
    for c in &r.components { for d in &c.embedded { if seen.insert(d.cpe.clone()) {
        comps.push(json!({"type": "library", "bom-ref": d.cpe, "name": d.name, "version": d.version, "cpe": d.cpe,
                          "evidence": {"occurrences": r.components.iter().filter(|x| x.embedded.contains(d)).map(|x| json!({"location": x.path})).collect::<Vec<_>>()}}));
    } } }
    let by_name: BTreeMap<String, &str> = r.components.iter().flat_map(|c| {
        let mut v = vec![(c.path.rsplit('/').next().unwrap_or("").to_string(), c.path.as_str())];
        if let Some(s) = c.elf.as_ref().and_then(|e| e.soname.clone()) { v.push((s, c.path.as_str())); }
        v }).collect();
    let deps: Vec<Value> = r.components.iter().filter_map(|c| { let e = c.elf.as_ref()?; if e.needed.is_empty() { return None; }
        let on: Vec<&str> = e.needed.iter().filter_map(|n| by_name.get(n).copied()).collect();
        Some(json!({"ref": c.path, "dependsOn": on})) }).collect();
    json!({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"component": {"type": "firmware", "name": source}, "tools": [{"name": "ifscan", "version": env!("CARGO_PKG_VERSION")}]},
           "components": comps, "dependencies": deps})
}
