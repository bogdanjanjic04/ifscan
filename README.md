# ifscan

Inspect a QNX image filesystem (IFS) on any Linux, macOS or Windows host, without a target and without booting it.

`ifscan` answers three questions about an image before it ships:

1. **What is in it?** Every file, with mode, owner and SHA-256.
2. **What third-party code is in it?** Libraries are identified by the version banner they compile into themselves (OpenSSL, zlib, curl, BusyBox, OpenSSH and others) and reported with CPE names; `ifscan vulns` then looks those up in the NVD and lists the known CVEs.
3. **Is it built safely?** Each ELF binary is checked for PIE, RELRO, non-executable stack and stack protector; setuid and world-writable files are flagged; libraries that binaries need but the image does not contain are listed.

The result is printed for people or written as a CycloneDX 1.5 software bill of materials for tools.

## Usage

```
ifscan ls <image>              list contents
ifscan audit <image> [--json]  findings; exit code 2 if any are high severity
ifscan components <image>      third-party components with CPE names
ifscan vulns <image> [--min-score 7] [--json]   known CVEs for those components (queries the NVD)
ifscan vulns --cpe <cpe-name>  look up a single component
ifscan sbom <image> -o bom.json
ifscan extract <image> <dir>
```

`audit` exits with status 2 when a high-severity finding exists, so it can gate a CI pipeline. `vulns` does the same when any CVE scores 7.0 or higher.

`vulns` is the only command that uses the network, and it sends only CPE names; the image never leaves the machine. Without an API key the NVD allows 5 requests per 30 seconds, so ifscan paces itself; set `NVD_API_KEY` to go faster.

## Build

```
cargo build --release
cargo test
```

Requires Rust 1.74 or newer. No QNX tools are needed on the host.

## Status and limits

- Reads image filesystems with or without a startup header, little- or big-endian. The header layout was checked field by field against the public `sys/image.h` and `sys/startup.h`.
- Unpacks zlib- and LZO-compressed images, using the block framing the open-source `dumpifs` reads. LZ4 is unpacked on the assumption that it uses the same framing; that has not been confirmed against an image built by `mkifs`. UCL images are reported but not unpacked.
- Checked against a real image built with `mkifs`: the Raspberry Pi image in the public [varghes/Raspberry-QNX](https://github.com/varghes/Raspberry-QNX) board support package (ARM, uncompressed). ifscan lists its 238 entries and 136 ELF binaries, and finds OpenSSL 1.0.0e, libpng 1.4.0 and two zlib versions in it. That image predates QNX 8.0; the image header structures are unchanged in the public headers, but a run on an image built with SDP 8.0 has not been recorded yet.
- The automated tests build their images in memory, including the compressed ones.
- Binaries from the QNX toolchain carry no `PT_GNU_STACK` header, so ifscan reports an executable stack only when a binary explicitly asks for one.
- Component detection relies on version banners; a library stripped of its banner is not identified.
- The CVE list is what the NVD records for that upstream version. It does not know about fixes a vendor backported without changing the version string, so treat it as a list to review, not a verdict.

## Licence

Apache-2.0
