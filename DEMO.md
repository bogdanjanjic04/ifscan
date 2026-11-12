# Demo video script (target 2:40, limit 3:00)

Record the terminal at a large font size. Speak the lines in quotes or put them on screen as captions.

| Time | On screen | Say |
|---|---|---|
| 0:00 | Title card: "ifscan: know what is inside a QNX image before it ships" | "A QNX image is one opaque file. Once it is built, most teams cannot easily say what is in it." |
| 0:15 | `ifscan ls ifs-bcm2835.bin` scrolling | "ifscan reads the image filesystem directly on the host. No target, no boot, no QNX tools needed." |
| 0:35 | `ifscan audit ifs-bcm2835.bin` | "It checks every binary for PIE, RELRO, executable stack and stack protector, and flags setuid and world-writable files." |
| 1:00 | `echo $?` showing 2, then a CI config snippet | "High-severity findings return exit code 2, so one line in CI stops a bad image." |
| 1:15 | `ifscan components ifs-bcm2835.bin` | "QNX images have no package database. ifscan identifies third-party libraries from the version banners compiled into them." |
| 1:35 | `ifscan vulns ifs-bcm2835.bin --min-score 7` | "Then it asks the NVD which known vulnerabilities apply to exactly those versions. Only component names leave the machine." |
| 2:05 | `ifscan sbom ifs-bcm2835.bin -o bom.json`, open the file | "And it writes a CycloneDX bill of materials for the compliance tools you already use." |
| 2:25 | Repo URL, licence line | "ifscan is open source under Apache 2.0, written in Rust, and runs on Linux, macOS and Windows." |

Before recording: run each command once on the image and check the output. The image used here is the public Raspberry Pi one named in the README.
