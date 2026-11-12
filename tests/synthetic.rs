//! Builds a small image in memory with the documented layout and checks the reader against it.
use ifscan::{ifs::{self, EntryKind}, sbom};

fn dirent(mode: u32, ino: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let size = ((24 + body.len() + 3) / 4 * 4) as u16;
    v.extend(size.to_le_bytes()); v.extend(0u16.to_le_bytes());
    v.extend(ino.to_le_bytes()); v.extend(mode.to_le_bytes());
    v.extend(0u32.to_le_bytes()); v.extend(0u32.to_le_bytes()); v.extend(1_700_000_000u32.to_le_bytes());
    v.extend(body); v.resize(size as usize, 0); v
}

fn build(with_startup: bool) -> Vec<u8> {
    let exe_v = std::fs::read(env!("CARGO_BIN_EXE_ifscan")).unwrap();
    let exe: &[u8] = &exe_v;
    let script = b"#!/bin/sh\necho hi\n#OpenSSL 3.0.13 30 Jan 2024\n";
    let hdr_len = 92usize;
    // two passes: directory size is needed to place file data
    let mk = |off_a: u32, off_b: u32| {
        let mut d = dirent(0o040755, 1, b"proc/boot\0");
        let mut b = Vec::new(); b.extend(off_a.to_le_bytes()); b.extend((script.len() as u32).to_le_bytes()); b.extend(b"proc/boot/startup.sh\0");
        d.extend(dirent(0o100666, 2, &b));
        let mut b = Vec::new(); b.extend(off_b.to_le_bytes()); b.extend((exe.len() as u32).to_le_bytes()); b.extend(b"proc/boot/ifscan\0");
        d.extend(dirent(0o104755, 3, &b));
        let mut b = Vec::new(); b.extend(4u16.to_le_bytes()); b.extend(9u16.to_le_bytes()); b.extend(b"bin\0proc/boot");
        d.extend(dirent(0o120777, 4, &b));
        d.extend([0u8; 4]); d
    };
    let dlen = mk(0, 0).len();
    let off_a = (hdr_len + dlen) as u32; let off_b = off_a + script.len() as u32;
    let dir = mk(off_a, off_b);
    let total = off_b as usize + exe.len() + 4;
    let mut img = Vec::new();
    img.extend(b"imagefs"); img.push(0);
    img.extend((total as u32).to_le_bytes());
    img.extend(((hdr_len + dir.len()) as u32).to_le_bytes());
    img.extend((hdr_len as u32).to_le_bytes());
    img.extend([3u32, 0, 0, 0].iter().flat_map(|x| x.to_le_bytes()));
    img.extend(2u32.to_le_bytes()); img.extend(0u32.to_le_bytes());
    img.extend([0u8; 40]); img.extend(0u32.to_le_bytes()); img.extend(b"/\0\0\0");
    assert_eq!(img.len(), hdr_len);
    img.extend(dir); img.extend(script); img.extend(exe); img.extend([0u8; 4]);
    if !with_startup { return img; }
    let mut out = vec![0u8; 256];
    out[..4].copy_from_slice(&ifs::STARTUP_SIG.to_le_bytes());
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[8..10].copy_from_slice(&256u16.to_le_bytes());
    out[10..12].copy_from_slice(&183u16.to_le_bytes());
    out[32..36].copy_from_slice(&256u32.to_le_bytes());
    out.extend(img); out
}

#[test]
fn reads_bare_and_wrapped_images() {
    for wrapped in [false, true] {
        let data = build(wrapped);
        let img = ifs::parse(&data).unwrap();
        assert_eq!(img.startup.is_some(), wrapped);
        assert_eq!(img.mountpoint, "/");
        assert_eq!(img.entries.len(), 4);
        assert_eq!(img.entries[1].path, "proc/boot/startup.sh");
        assert_eq!(img.file_data(&data, &img.entries[1]).unwrap(), b"#!/bin/sh\necho hi\n#OpenSSL 3.0.13 30 Jan 2024\n");
        
        assert!(matches!(&img.entries[3].kind, EntryKind::Symlink { target } if target == "proc/boot"));
        let r = sbom::build(img, &data);
        assert_eq!(r.components.len(), 2);
        let exe = r.components.iter().find(|c| c.path.ends_with("ifscan")).unwrap();
        let elf = exe.elf.as_ref().expect("host binary should parse as ELF");
        assert_eq!(elf.kind, "executable");
        assert!(exe.setuid);
        assert!(r.findings.iter().any(|f| f.rule == "world-writable" && f.path.ends_with("startup.sh")));
        assert!(r.findings.iter().any(|f| f.rule == "setuid"));
        let bom = sbom::cyclonedx(&r, "test.ifs");
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert!(bom["components"].as_array().unwrap().iter().any(|c| c["cpe"] == "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"));
    }
}

#[test]
fn rejects_garbage() {
    assert!(ifs::parse(b"definitely not an image").is_err());
    assert!(ifs::parse(b"imagefs\0\xff\xff\xff\xff\0\0\0\0").is_err());
}

/// Wraps the plain image the way a compressed one is stored: startup in the clear, filesystem packed.
fn compress(plain: &[u8], kind: u8) -> Vec<u8> {
    let (head, fs) = plain.split_at(256);
    let mut out = head.to_vec();
    out[6] |= kind << 2;
    let framed = |enc: &dyn Fn(&[u8]) -> Vec<u8>| {
        let mut v = Vec::new();
        for chunk in fs.chunks(16 * 1024) {
            let c = enc(chunk);
            v.extend((c.len() as u16).to_be_bytes()); v.extend(c);
        }
        v.extend([0u8, 0]); v
    };
    match kind {
        1 => {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(fs).unwrap(); out.extend(e.finish().unwrap());
        }
        2 => out.extend(framed(&|c| lzokay_native::compress(c).unwrap())),
        4 => out.extend(framed(&|c| lz4_flex::block::compress(c))),
        _ => unreachable!(),
    }
    out
}

#[test]
fn unpacks_compressed_images() {
    let plain = build(true);
    assert!(matches!(ifs::unpack(&plain).unwrap(), std::borrow::Cow::Borrowed(_)));
    for kind in [1u8, 2, 4] {
        let packed = compress(&plain, kind);
        assert!(ifs::parse(&packed).is_err(), "packed image must not parse directly");
        let data = ifs::unpack(&packed).unwrap();
        let img = ifs::parse(&data).unwrap();
        assert_eq!(img.entries.len(), 4, "compression kind {kind}");
        assert_eq!(img.file_data(&data, &img.entries[1]).unwrap().len(), 46);
    }
}
