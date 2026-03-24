# Executable Quick Viewer

Read-only executable metadata preview for [Nuclr Commander](https://nuclr.dev), with support for Windows PE, Linux ELF, and macOS Mach-O binaries.

![Executable Quick Viewer Screenshot](images/screenshot-1.jpg)

## Overview

This plugin adds a quick-view panel for executable files. It is built for the common "what is this binary?" workflow: inspect the container format, architecture, bitness, endianness, entry information, selected flags, and section or slice layout without leaving the file manager.

The parser is intentionally conservative. It reads stable header metadata only and does not execute the file, invoke native helper tools, or attempt deep reverse engineering.

## Supported Formats

| Platform | Format | Typical files |
|---|---|---|
| Windows | PE / COFF | `.exe`, `.dll`, `.sys`, `.ocx` |
| Linux / Unix | ELF | executables, `.so`, AppImage-style binaries |
| macOS | Mach-O | executables, `.dylib`, `.bundle`, `.o` |
| macOS | Universal / Fat Mach-O | multi-architecture binaries |

## What The Viewer Shows

- File summary: name, size, container format, type, platform, architecture, bitness, endianness
- Header details: machine / CPU type, subsystem, ABI, image base, entrypoint, interpreter, loader hints
- Common flags: ASLR, NX, PIE, dynamic linking, stripped hints where available
- Structure listing: PE sections, ELF sections, Mach-O sections, or fat-binary slices

## What It Does Not Do

- Disassembly
- Decompilation
- Import / export browsing
- Signature verification
- Malware analysis
- Binary execution

If a field is not generally available in the standard executable headers, this plugin usually does not attempt to infer it.

## Screenshot

The example below shows the quick-view panel rendering executable metadata directly inside Nuclr Commander:

![Quick View Panel](images/screenshot-1.jpg)

## Build

Requirements:

- Java 21+
- Maven 3.9+
- `plugins-sdk` installed locally

Commands:

```bash
mvn test
mvn clean package
```

If your environment is configured for signing:

```bash
mvn clean verify -Djarsigner.storepass=<keystore-password>
```

Build artifacts are written to `target/`.

## Installation

Copy the packaged plugin archive into the Nuclr Commander `plugins/` directory:

```text
quick-view-executables-1.0.0.zip
```

If your setup expects signed plugins, also copy:

```text
quick-view-executables-1.0.0.zip.sig
```

## Repository Layout

```text
src/
|- main/java/dev/nuclr/plugin/core/quick/viewer/
|  |- ExecutableQuickViewProvider.java
|  |- ExecutableViewPanel.java
|  `- exec/
|     |- ExecutableParser.java
|     |- ExecutableFileInfo.java
|     |- ExecutableTableEntry.java
|     `- ExecutableParseException.java
|- main/resources/
|  `- plugin.json
`- test/java/dev/nuclr/plugin/core/quick/viewer/exec/
   `- ExecutableParserTest.java
```

## Testing

The repository includes parser-focused tests covering:

- PE metadata extraction
- ELF metadata extraction
- Fat Mach-O parsing
- Unsupported file handling

## License

Apache License 2.0.
