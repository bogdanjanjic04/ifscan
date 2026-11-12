use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ifscan::{ifs, sbom, vulns};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(version, about = "Inspect QNX image filesystems (IFS) on any host")]
struct Cli { #[command(subcommand)] cmd: Cmd }

#[derive(Subcommand)]
enum Cmd {
    /// List the contents of an image
    Ls { image: PathBuf },
    /// Audit binaries in an image and print findings
    Audit { image: PathBuf, #[arg(long)] json: bool, /// List every finding, not only the high-severity ones
        #[arg(long)] all: bool },
    /// Write a CycloneDX 1.5 software bill of materials
    Sbom { image: PathBuf, #[arg(short, long)] output: Option<PathBuf> },
    /// List third-party components found by their version banners, with CPE names
    Components { image: PathBuf },
    /// Look up known vulnerabilities (NVD) for the components found in an image
    Vulns {
        /// Image to scan; omit when using --cpe
        image: Option<PathBuf>,
        /// Look up one CPE name directly instead of scanning an image
        #[arg(long)] cpe: Option<String>,
        #[arg(long)] json: bool,
        /// Only report vulnerabilities with at least this CVSS base score
        #[arg(long, default_value_t = 0.0)] min_score: f64,
    },
    /// Extract every regular file into a directory
    Extract { image: PathBuf, dir: PathBuf },
}

fn load(p: &PathBuf) -> Result<(Vec<u8>, ifs::Image)> {
    let raw = fs::read(p).with_context(|| format!("cannot read {}", p.display()))?;
    let data = ifs::unpack(&raw)?.into_owned();
    let img = ifs::parse(&data)?;
    Ok((data, img))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Ls { image } => {
            let (_, img) = load(&image)?;
            if let Some(s) = &img.startup { println!("startup: version {} machine {} compression {:?} ram {:#x}", s.version, s.machine, s.compression, s.ram_size); }
            println!("imagefs at {:#x}, {} bytes, mountpoint \"{}\", {} entries", img.image_offset, img.image_size, img.mountpoint, img.entries.len());
            for e in &img.entries {
                let (t, extra) = match &e.kind {
                    ifs::EntryKind::File { size, .. } => ('-', format!("{size:>10}")),
                    ifs::EntryKind::Dir => ('d', format!("{:>10}", "")),
                    ifs::EntryKind::Symlink { target } => ('l', format!("-> {target}")),
                    ifs::EntryKind::Device { .. } => ('c', format!("{:>10}", "")),
                };
                println!("{t}{:04o} {:>5} {:>5} {extra} {}", e.mode & 0o7777, e.uid, e.gid, e.path);
            }
        }
        Cmd::Audit { image, json, all } => {
            let (data, img) = load(&image)?;
            let r = sbom::build(img, &data);
            if json { println!("{}", serde_json::to_string_pretty(&r)?); return Ok(()); }
            let elf = r.components.iter().filter(|c| c.elf.is_some()).count();
            println!("{} files, {} ELF binaries, {} findings", r.components.len(), elf, r.findings.len());
            let mut counts: std::collections::BTreeMap<(&str, &str), usize> = Default::default();
            for f in &r.findings { *counts.entry((f.severity, f.rule)).or_default() += 1; }
            for sev in ["high", "medium", "low", "info"] {
                for ((s, rule), n) in counts.iter().filter(|((s, _), _)| *s == sev) { println!("  {s:<6} {rule:<20} {n}"); }
            }
            if !all { println!("(use --all to list every finding below high severity)"); }
            for sev in ["high", "medium", "low", "info"] {
                if !all && sev != "high" { continue; }
                for f in r.findings.iter().filter(|f| f.severity == sev) { println!("{:<6} {:<20} {}  ({})", f.severity, f.rule, f.path, f.detail); }
            }
            if r.findings.iter().any(|f| f.severity == "high") { std::process::exit(2); }
        }
        Cmd::Sbom { image, output } => {
            let (data, img) = load(&image)?;
            let name = image.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let s = serde_json::to_string_pretty(&sbom::cyclonedx(&sbom::build(img, &data), &name))?;
            match output { Some(p) => fs::write(p, s)?, None => println!("{s}") }
        }
        Cmd::Components { image } => {
            let (data, img) = load(&image)?;
            let r = sbom::build(img, &data);
            let mut rows: Vec<(String, String, String)> = r.components.iter().flat_map(|c| c.embedded.iter().map(move |d| (format!("{} {}", d.name, d.version), d.cpe.clone(), c.path.clone()))).collect();
            rows.sort(); rows.dedup();
            if rows.is_empty() { println!("no known version banners found"); }
            for (n, cpe, path) in rows { println!("{n:<22} {cpe}  in {path}"); }
        }
        Cmd::Vulns { image, cpe, json, min_score } => {
            // (label, cpe, files)
            let targets: Vec<(String, String, Vec<String>)> = match (cpe, image) {
                (Some(c), _) => vec![(c.clone(), c, vec![])],
                (None, Some(image)) => {
                    let (data, img) = load(&image)?;
                    let r = sbom::build(img, &data);
                    let mut m: std::collections::BTreeMap<(String, String), Vec<String>> = Default::default();
                    for c in &r.components { for d in &c.embedded { m.entry((format!("{} {}", d.name, d.version), d.cpe.clone())).or_default().push(c.path.clone()); } }
                    m.into_iter().map(|((n, c), f)| (n, c, f)).collect()
                }
                (None, None) => anyhow::bail!("give an image or --cpe"),
            };
            let key = std::env::var("NVD_API_KEY").ok();
            let mut all = Vec::new();
            for (i, (label, cpe, files)) in targets.iter().enumerate() {
                if i > 0 && key.is_none() { std::thread::sleep(std::time::Duration::from_secs(6)); }
                if !json { eprintln!("querying NVD for {label} ..."); }
                let mut v = vulns::lookup(cpe, key.as_deref())?;
                v.retain(|x| x.score.unwrap_or(0.0) >= min_score);
                all.push((label, cpe, files, v));
            }
            if json {
                let out: Vec<_> = all.iter().map(|(l, c, f, v)| serde_json::json!({"component": l, "cpe": c, "files": f, "vulnerabilities": v})).collect();
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                if all.is_empty() { println!("no known version banners found, nothing to look up"); }
                for (label, _, files, v) in &all {
                    println!("{label}: {} known vulnerabilities{}", v.len(), if files.is_empty() { String::new() } else { format!("  (in {})", files.join(", ")) });
                    for x in v { println!("  {:<16} {:<8} {:>4}  {}  {}", x.id, x.severity, x.score.map(|s| format!("{s:.1}")).unwrap_or_else(|| "-".into()), x.published, x.summary.chars().take(110).collect::<String>()); }
                }
            }
            if all.iter().any(|(_, _, _, v)| v.iter().any(|x| x.score.unwrap_or(0.0) >= 7.0)) { std::process::exit(2); }
        }
        Cmd::Extract { image, dir } => {
            let (data, img) = load(&image)?;
            let mut n = 0;
            for e in &img.entries {
                let Some(bytes) = img.file_data(&data, e) else { continue };
                let rel: PathBuf = e.path.split('/').filter(|c| !c.is_empty() && *c != "." && *c != "..").collect();
                let out = dir.join(rel);
                if let Some(p) = out.parent() { fs::create_dir_all(p)?; }
                fs::write(&out, bytes)?; n += 1;
            }
            println!("extracted {n} files to {}", dir.display());
        }
    }
    Ok(())
}
