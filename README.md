# Executable Quick Viewer

🔎🧩 A [Nuclr Commander](https://nuclr.dev) plugin for fast, safe, read-only previews of executable files across **Windows**, **Linux**, and **macOS**.

Instead of dumping raw bytes or trying to behave like a disassembler, this plugin focuses on the **generally available metadata** that is useful at a glance:

- 🪟 **PE / COFF**: `.exe`, `.dll`, `.sys`, `.ocx`
- 🐧 **ELF**: `.so`, `.bin`, `.run`, AppImage-style binaries
- 🍎 **Mach-O**: `.dylib`, `.bundle`, `.o`, universal / fat binaries

It never executes the target file. No sandbox escapes, no native helper tools, no platform-specific runtime dependencies. Just parse the headers and show the useful bits. ✅

---

## ✨ What You See

The quick view panel is designed for a fast "what is this binary?" pass.

### 📋 Summary
- File name
- File size
- Container / format
- Executable type
- Architecture
- Bitness
- Endianness
- Platform

### 🧠 Details
- Entrypoint / RVA
- Image base
- Machine / CPU type
- Loader / subsystem
- Security-related flags such as ASLR / NX / PIE where available
- Linkage hints such as dynamic vs static where available
- Timestamps and ABI information where available

### 🧱 Structure
- PE sections
- ELF sections
- Mach-O sections
- Universal Mach-O architecture slices

---

## 🌍 Cross-Platform Coverage

This plugin recognizes the three major executable families:

| Platform | Format | Examples |
|---|---|---|
| 🪟 Windows | PE / COFF | `.exe`, `.dll`, `.sys` |
| 🐧 Linux / Unix | ELF | executables, shared objects |
| 🍎 macOS | Mach-O | executables, dylibs, bundles |

Universal / fat Mach-O binaries are also supported, with per-slice architecture listing. 🍏📦

---

## 🛡️ Design Goals

- ⚡ **Fast**: reads lightweight header metadata only
- 🔒 **Safe**: never executes the file being previewed
- 🧾 **Practical**: shows stable, widely understood metadata instead of deep reverse-engineering output
- 🧰 **Portable**: implemented in Java with no native parsing dependency
- 👀 **Quick-view friendly**: optimized for glanceable inspection inside Nuclr Commander

---

## 🚫 Out of Scope

This plugin is intentionally conservative.

It does **not** try to provide:

- ❌ disassembly
- ❌ decompilation
- ❌ symbol browsing UI
- ❌ import/export trees
- ❌ signature verification
- ❌ malware analysis
- ❌ code execution or runtime probing

If the information is not generally available from the standard binary headers, it is probably not shown here.

---

## 📦 Installation

Copy the built plugin archive into your Nuclr Commander `plugins/` directory:

```text
quick-view-executables-1.0.0.zip
```

If you use signed plugin deployment in your local setup, also copy:

```text
quick-view-executables-1.0.0.zip.sig
```

---

## 🛠️ Building

Requirements:

- ☕ Java 21+
- 🧱 Maven 3.9+
- 🧩 `plugins-sdk` installed locally

Build the plugin:

```bash
mvn clean package
```

Run tests:

```bash
mvn test
```

Create signed artifacts if your environment is configured for signing:

```bash
mvn clean verify -Djarsigner.storepass=<keystore-password>
```

Artifacts are produced in `target/`. 🎯

---

## 🧪 Test Coverage

The plugin includes parser-focused tests for:

- 🪟 PE metadata extraction
- 🐧 ELF metadata extraction
- 🍎 Fat Mach-O parsing
- 🚨 unsupported / invalid file handling

---

## 🏗️ Source Layout

```text
src/
├── main/java/dev/nuclr/plugin/core/quick/viewer/
│   ├── ExecutableQuickViewProvider.java
│   ├── ExecutableViewPanel.java
│   └── exec/
│       ├── ExecutableParser.java
│       ├── ExecutableFileInfo.java
│       ├── ExecutableTableEntry.java
│       └── ExecutableParseException.java
├── main/resources/
│   └── plugin.json
└── test/java/dev/nuclr/plugin/core/quick/viewer/exec/
    └── ExecutableParserTest.java
```

---

## ❤️ Why This Exists

Sometimes you do not want to open a terminal, run `file`, or feed a binary into a heavyweight analysis tool just to answer simple questions like:

- 🤔 Is this PE, ELF, or Mach-O?
- 🧭 Which architecture is it built for?
- 🧱 Is it a DLL / shared object / bundle?
- 🔐 Does it expose common security flags?
- 📚 What sections or slices does it contain?

This plugin answers those questions directly inside Nuclr Commander.

---

## 📄 License

Apache License 2.0.
