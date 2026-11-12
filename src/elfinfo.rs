//! Facts extracted from ELF binaries found inside an image.
use object::read::elf::{ElfFile32, ElfFile64, FileHeader, ProgramHeader, Dyn};
use object::{elf, Endianness, Object, ObjectSection};
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ElfInfo {
    pub arch: String,
    pub kind: String,
    pub soname: Option<String>,
    pub needed: Vec<String>,
    pub build_id: Option<String>,
    /// PIE, RELRO, BIND_NOW, non-executable stack, stack protector.
    pub hardening: Hardening,
    pub stripped: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Hardening { pub pie: bool, pub relro: bool, pub bind_now: bool, /// None when the binary has no PT_GNU_STACK header, as with binaries from the QNX toolchain.
    pub nx_stack: Option<bool>, pub stack_protector: bool }

pub fn is_elf(d: &[u8]) -> bool { d.len() > 4 && &d[..4] == b"\x7fELF" }

pub fn inspect(d: &[u8]) -> Option<ElfInfo> {
    if !is_elf(d) { return None; }
    match d.get(4)? {
        1 => inspect_t::<elf::FileHeader32<Endianness>>(d, ElfFile32::parse(d).ok().map(Generic::A)),
        2 => inspect_t::<elf::FileHeader64<Endianness>>(d, ElfFile64::parse(d).ok().map(Generic::B)),
        _ => None,
    }
}

enum Generic<'a> { A(ElfFile32<'a, Endianness>), B(ElfFile64<'a, Endianness>) }

fn inspect_t<'a, H: FileHeader<Endian = Endianness>>(d: &'a [u8], g: Option<Generic<'a>>) -> Option<ElfInfo> {
    let h = H::parse(d).ok()?;
    let e = h.endian().ok()?;
    let mut info = ElfInfo::default();
    info.arch = match h.e_machine(e) {
        elf::EM_AARCH64 => "aarch64", elf::EM_X86_64 => "x86_64", elf::EM_ARM => "arm",
        elf::EM_386 => "x86", elf::EM_RISCV => "riscv", elf::EM_PPC => "ppc", elf::EM_MIPS => "mips",
        _ => "unknown",
    }.to_string();
    let etype = h.e_type(e);
    let phs = h.program_headers(e, d).ok()?;
    let mut has_interp = false;
    let mut flags = 0u64; let mut flags1 = 0u64;
    for ph in phs {
        match ph.p_type(e) {
            elf::PT_INTERP => has_interp = true,
            elf::PT_GNU_RELRO => info.hardening.relro = true,
            elf::PT_GNU_STACK => info.hardening.nx_stack = Some(ph.p_flags(e) & elf::PF_X == 0),
            elf::PT_DYNAMIC => {
                if let Ok(Some(dyns)) = ph.dynamic(e, d) {
                    let mut strtab = 0u64; let mut strsz = 0u64;
                    for dn in dyns { let t = dn.d_tag(e).into(); let v: u64 = dn.d_val(e).into();
                        if t == elf::DT_STRTAB as u64 { strtab = v } else if t == elf::DT_STRSZ as u64 { strsz = v } }
                    // map strtab vaddr -> file offset through PT_LOAD
                    let off = phs.iter().find_map(|p| { let (va, fo, fs): (u64,u64,u64) = (p.p_vaddr(e).into(), p.p_offset(e).into(), p.p_filesz(e).into());
                        (p.p_type(e) == elf::PT_LOAD && strtab >= va && strtab < va + fs).then(|| fo + (strtab - va)) });
                    let tab = off.and_then(|o| d.get(o as usize..(o + strsz) as usize));
                    let s = |v: u64| tab.and_then(|t| t.get(v as usize..)).map(|b| { let n = b.iter().position(|&c| c == 0).unwrap_or(b.len()); String::from_utf8_lossy(&b[..n]).into_owned() });
                    for dn in dyns { let t: u64 = dn.d_tag(e).into(); let v: u64 = dn.d_val(e).into();
                        if t == elf::DT_NEEDED as u64 { if let Some(x) = s(v) { info.needed.push(x) } }
                        else if t == elf::DT_SONAME as u64 { info.soname = s(v) }
                        else if t == elf::DT_FLAGS as u64 { flags = v }
                        else if t == elf::DT_FLAGS_1 as u64 { flags1 = v }
                        else if t == elf::DT_BIND_NOW as u64 { info.hardening.bind_now = true } }
                }
            }
            elf::PT_NOTE => {
                if let Ok(Some(mut notes)) = ph.notes(e, d) {
                    while let Ok(Some(n)) = notes.next() {
                        if n.name() == b"GNU" && n.n_type(e) == elf::NT_GNU_BUILD_ID {
                            info.build_id = Some(n.desc().iter().map(|b| format!("{b:02x}")).collect());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if flags & elf::DF_BIND_NOW as u64 != 0 || flags1 & elf::DF_1_NOW as u64 != 0 { info.hardening.bind_now = true; }
    let pie_flag = flags1 & elf::DF_1_PIE as u64 != 0;
    info.kind = match etype {
        elf::ET_EXEC => "executable",
        elf::ET_DYN if has_interp || pie_flag => "executable",
        elf::ET_DYN => "shared-library",
        elf::ET_REL => "object",
        _ => "other",
    }.to_string();
    info.hardening.pie = etype == elf::ET_DYN && info.kind == "executable";
    // Symbol-level facts need section headers; absent on fully stripped files.
    let (has_symtab, has_chk) = match &g {
        Some(Generic::A(f)) => sym_facts(f, d), Some(Generic::B(f)) => sym_facts(f, d), None => (false, false),
    };
    info.stripped = !has_symtab;
    info.hardening.stack_protector = has_chk;
    Some(info)
}

fn sym_facts<'a, O: Object<'a>>(f: &O, _d: &[u8]) -> (bool, bool) {
    let has_symtab = f.section_by_name(".symtab").is_some();
    let chk = [".dynstr", ".strtab"].iter().any(|n| f.section_by_name(n).and_then(|s| s.data().ok())
        .map(|b| memchr::memmem::find(b, b"__stack_chk_fail").is_some()).unwrap_or(false));
    (has_symtab, chk)
}
