//! Reader for the QNX image filesystem (IFS) container.
//!
//! Layout follows the public `sys/image.h` / `sys/startup.h` definitions:
//! an optional startup header (signature 0x00ff7eeb) followed by an
//! `imagefs` header, a directory of variable-length entries and file data.
use anyhow::{anyhow, bail, Result};
use serde::Serialize;

pub const STARTUP_SIG: u32 = 0x00ff_7eeb;
pub const IMAGE_SIG: &[u8; 7] = b"imagefs";
const FLAG_BIGENDIAN: u8 = 0x01;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression { None, Zlib, Lzo, Ucl, Lz4, Unknown }

#[derive(Debug, Clone, Serialize)]
pub struct StartupHeader {
    pub offset: usize,
    pub version: u16,
    pub machine: u16,
    pub compression: Compression,
    pub startup_size: u32,
    pub stored_size: u32,
    pub imagefs_size: u32,
    pub image_paddr: u32,
    pub ram_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum EntryKind {
    File { offset: u32, size: u32 },
    Dir,
    Symlink { target: String },
    Device { dev: u32, rdev: u32 },
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub path: String,
    pub ino: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    #[serde(flatten)]
    pub kind: EntryKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct Image {
    pub startup: Option<StartupHeader>,
    pub image_offset: usize,
    pub big_endian: bool,
    pub image_size: u32,
    pub mountpoint: String,
    pub boot_inodes: Vec<u32>,
    pub script_ino: u32,
    pub entries: Vec<Entry>,
}

struct Rd<'a> { d: &'a [u8], be: bool }
impl<'a> Rd<'a> {
    fn bytes(&self, off: usize, n: usize) -> Result<&'a [u8]> {
        self.d.get(off..off.checked_add(n).ok_or_else(|| anyhow!("offset overflow"))?)
            .ok_or_else(|| anyhow!("truncated image: need {n} bytes at {off:#x}"))
    }
    fn u16(&self, off: usize) -> Result<u16> {
        let b: [u8; 2] = self.bytes(off, 2)?.try_into().unwrap();
        Ok(if self.be { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) })
    }
    fn u32(&self, off: usize) -> Result<u32> {
        let b: [u8; 4] = self.bytes(off, 4)?.try_into().unwrap();
        Ok(if self.be { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }
    fn cstr(&self, off: usize, limit: usize) -> Result<String> {
        let end = limit.min(self.d.len());
        let s = self.d.get(off..end).ok_or_else(|| anyhow!("string out of range at {off:#x}"))?;
        let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        Ok(String::from_utf8_lossy(&s[..n]).into_owned())
    }
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    memchr::memmem::find(hay.get(from..)?, needle).map(|p| p + from)
}

pub fn find_startup(data: &[u8]) -> Option<StartupHeader> {
    // The signature is stored in the target's byte order; flags1 bit 1 says which.
    let le = find_startup_with(data, false);
    let be = find_startup_with(data, true);
    match (le, be) {
        (Some(a), Some(b)) => Some(if a.offset <= b.offset { a } else { b }),
        (a, b) => a.or(b),
    }
}

fn find_startup_with(data: &[u8], be: bool) -> Option<StartupHeader> {
    let sig = if be { STARTUP_SIG.to_be_bytes() } else { STARTUP_SIG.to_le_bytes() };
    let mut from = 0;
    while let Some(off) = find(data, &sig, from) {
        let r = Rd { d: data, be };
        if let (Ok(hsz), Ok(ver), Some(&flags1)) = (r.u16(off + 8), r.u16(off + 4), data.get(off + 6)) {
            if hsz >= 0x40 && hsz <= 0x400 && (flags1 & 0x02 != 0) == be {
                let compression = match (flags1 >> 2) & 7 {
                    0 => Compression::None, 1 => Compression::Zlib, 2 => Compression::Lzo,
                    3 => Compression::Ucl, 4 => Compression::Lz4, _ => Compression::Unknown,
                };
                return Some(StartupHeader {
                    offset: off, version: ver, machine: r.u16(off + 10).ok()?, compression,
                    image_paddr: r.u32(off + 20).ok()?, ram_size: r.u32(off + 28).ok()?,
                    startup_size: r.u32(off + 32).ok()?, stored_size: r.u32(off + 36).ok()?,
                    imagefs_size: r.u32(off + 44).ok()?,
                });
            }
        }
        from = off + 4;
    }
    None
}

/// Sanity cap on the unpacked size of a compressed image (1 GiB).
const MAX_UNPACKED: usize = 1 << 30;

/// Returns the image with its filesystem decompressed. Uncompressed images are borrowed as-is.
///
/// A compressed image keeps the startup program in the clear and stores the filesystem
/// after it, either as one gzip/zlib stream or as blocks prefixed by a 16-bit big-endian
/// length and ended by a zero length (the framing `dumpifs` reads for LZO and UCL).
pub fn unpack(data: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>> {
    use std::borrow::Cow;
    let Some(s) = find_startup(data) else { return Ok(Cow::Borrowed(data)) };
    if s.compression == Compression::None { return Ok(Cow::Borrowed(data)); }
    let start = s.offset.checked_add(s.startup_size as usize).filter(|&p| p <= data.len())
        .ok_or_else(|| anyhow!("startup size {:#x} runs past the end of the file", s.startup_size))?;
    let body = &data[start..];
    let fs = match s.compression {
        Compression::Zlib => inflate(body)?,
        Compression::Lzo => blocks(body, |b| lzokay_native::decompress_all(b, None).map_err(|e| anyhow!("LZO block: {e:?}")))?,
        Compression::Lz4 => blocks(body, |b| lz4_flex::block::decompress(b, 1 << 20).map_err(|e| anyhow!("LZ4 block: {e}")))?,
        c => bail!("image filesystem is {c:?}-compressed, which ifscan cannot unpack yet"),
    };
    let mut out = data[..start].to_vec();
    // Clear the compression bits so the result reads as a plain image.
    out[s.offset + 6] &= !0x1c;
    out.extend_from_slice(&fs);
    Ok(Cow::Owned(out))
}

fn inflate(body: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    let limit = MAX_UNPACKED as u64;
    let r = if body.starts_with(&[0x1f, 0x8b]) {
        flate2::read::MultiGzDecoder::new(body).take(limit).read_to_end(&mut out)
    } else if body.first() == Some(&0x78) {
        flate2::read::ZlibDecoder::new(body).take(limit).read_to_end(&mut out)
    } else {
        return blocks(body, |b| { let mut v = Vec::new(); flate2::read::ZlibDecoder::new(b).read_to_end(&mut v)?; Ok(v) });
    };
    // A trailing checksum after the stream makes the decoder complain once the data is out; keep what we got.
    if let Err(e) = r { if out.is_empty() { bail!("zlib stream: {e}"); } }
    Ok(out)
}

fn blocks(body: &[u8], dec: impl Fn(&[u8]) -> Result<Vec<u8>>) -> Result<Vec<u8>> {
    let (mut pos, mut out) = (0usize, Vec::new());
    loop {
        let len = match body.get(pos..pos + 2) { Some(b) => u16::from_be_bytes([b[0], b[1]]) as usize, None => break };
        if len == 0 { break; }
        let blk = body.get(pos + 2..pos + 2 + len).ok_or_else(|| anyhow!("compressed block at {pos:#x} is truncated"))?;
        out.extend(dec(blk).map_err(|e| anyhow!("{e} (block at {pos:#x})"))?);
        if out.len() > MAX_UNPACKED { bail!("unpacked image exceeds {MAX_UNPACKED} bytes"); }
        pos += 2 + len;
    }
    if out.is_empty() { bail!("no compressed blocks found after the startup program"); }
    Ok(out)
}

pub fn parse(data: &[u8]) -> Result<Image> {
    let startup = find_startup(data);
    // Literal runs in a packed filesystem can still contain a readable header, so refuse up front.
    if let Some(s) = startup.as_ref().filter(|s| s.compression != Compression::None) {
        bail!("image filesystem is {:?}-compressed; call ifs::unpack first", s.compression);
    }
    let search_from = startup.as_ref().map(|s| s.offset).unwrap_or(0);
    let mut from = search_from;
    let mut last_err = None;
    while let Some(off) = find(data, IMAGE_SIG, from) {
        match parse_at(data, off) {
            Ok(mut img) => { img.startup = startup; return Ok(img); }
            Err(e) => { last_err = Some(e); from = off + 1; }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no imagefs signature found: not a QNX IFS image")))
}

fn parse_at(data: &[u8], base: usize) -> Result<Image> {
    let flags = *data.get(base + 7).ok_or_else(|| anyhow!("truncated header"))?;
    let be = flags & FLAG_BIGENDIAN != 0;
    let r = Rd { d: data, be };
    let image_size = r.u32(base + 8)?;
    let hdr_dir_size = r.u32(base + 12)?;
    let dir_offset = r.u32(base + 16)?;
    if dir_offset < 92 || dir_offset > hdr_dir_size || (hdr_dir_size as u64) > image_size as u64 {
        bail!("implausible imagefs header at {base:#x}");
    }
    let boot_inodes = (0..4).map(|i| r.u32(base + 20 + i * 4)).collect::<Result<Vec<_>>>()?
        .into_iter().filter(|&i| i != 0).collect();
    let script_ino = r.u32(base + 36)?;
    let mountpoint = r.cstr(base + 88, base + dir_offset as usize)?;
    let dir_end = base + hdr_dir_size as usize;
    let mut pos = base + dir_offset as usize;
    let mut entries = Vec::new();
    while pos + 24 <= dir_end.min(data.len()) {
        let size = r.u16(pos)? as usize;
        if size == 0 { break; }
        if size < 24 || pos + size > data.len() { bail!("bad directory entry size {size} at {pos:#x}"); }
        let ino = r.u32(pos + 4)?;
        let mode = r.u32(pos + 8)?;
        let (gid, uid, mtime) = (r.u32(pos + 12)?, r.u32(pos + 16)?, r.u32(pos + 20)?);
        let end = pos + size;
        let (kind, path) = match mode & S_IFMT {
            S_IFREG => {
                let (o, s) = (r.u32(pos + 24)?, r.u32(pos + 28)?);
                (EntryKind::File { offset: o, size: s }, r.cstr(pos + 32, end)?)
            }
            S_IFDIR => (EntryKind::Dir, r.cstr(pos + 24, end)?),
            S_IFLNK => {
                let so = r.u16(pos + 24)? as usize;
                let ss = r.u16(pos + 26)? as usize;
                let path = r.cstr(pos + 28, end)?;
                let t = r.bytes(pos + 28 + so, ss.min(end.saturating_sub(pos + 28 + so)))?;
                (EntryKind::Symlink { target: String::from_utf8_lossy(t).trim_end_matches('\0').to_string() }, path)
            }
            _ => (EntryKind::Device { dev: r.u32(pos + 24)?, rdev: r.u32(pos + 28)? }, r.cstr(pos + 32, end)?),
        };
        // An inode of zero marks a deleted slot; the top bits are mkifs bookkeeping flags.
        if ino != 0 { entries.push(Entry { path, ino: ino & 0x1fff_ffff, mode, uid, gid, mtime, kind }); }
        pos = end;
    }
    if entries.is_empty() { bail!("imagefs at {base:#x} has no directory entries"); }
    Ok(Image { startup: None, image_offset: base, big_endian: be, image_size, mountpoint, boot_inodes, script_ino, entries })
}

impl Image {
    /// Bytes of a regular file, or None if the entry is not a file or lies outside the image.
    pub fn file_data<'a>(&self, data: &'a [u8], e: &Entry) -> Option<&'a [u8]> {
        match e.kind {
            EntryKind::File { offset, size } => {
                let s = self.image_offset.checked_add(offset as usize)?;
                data.get(s..s.checked_add(size as usize)?)
            }
            _ => None,
        }
    }
}
