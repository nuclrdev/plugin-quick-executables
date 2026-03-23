package dev.nuclr.plugin.core.quick.viewer.exec;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

public final class ExecutableParser {

	private static final int FAT_MAGIC = 0xCAFEBABE;
	private static final int FAT_CIGAM = 0xBEBAFECA;
	private static final int FAT_MAGIC_64 = 0xCAFEBABF;
	private static final int FAT_CIGAM_64 = 0xBFBAFECA;

	private ExecutableParser() {
	}

	public static ExecutableFileInfo parse(String fileName, byte[] data) throws ExecutableParseException {
		if (data.length < 4) {
			throw new ExecutableParseException("File is too small to inspect.");
		}
		if (isPe(data)) {
			return parsePe(data);
		}
		if (isElf(data)) {
			return parseElf(data);
		}
		if (isMachO(data)) {
			return parseMachO(data);
		}
		if (isFatMachO(data)) {
			return parseFatMachO(data);
		}
		throw new ExecutableParseException("Unrecognized executable format" + suffix(fileName) + ".");
	}

	private static ExecutableFileInfo parsePe(byte[] data) throws ExecutableParseException {
		BinaryReader r = BinaryReader.littleEndian(data);
		int peOffset = (int) r.u32(0x3C);
		r.requireRange(peOffset, 24, "Invalid PE header offset");
		if (r.u32(peOffset) != 0x00004550L) {
			throw new ExecutableParseException("Missing PE signature.");
		}

		int coff = peOffset + 4;
		int machine = r.u16(coff);
		int numberOfSections = r.u16(coff + 2);
		long timestamp = r.u32(coff + 4);
		int optionalHeaderSize = r.u16(coff + 16);
		int characteristics = r.u16(coff + 18);

		int optional = coff + 20;
		r.requireRange(optional, optionalHeaderSize, "PE optional header is truncated");
		int magic = r.u16(optional);
		boolean is64 = magic == 0x20B;
		if (!(magic == 0x10B || magic == 0x20B)) {
			throw new ExecutableParseException("Unsupported PE optional header type.");
		}

		long entryPoint = r.u32(optional + 16);
		long imageBase = is64 ? r.u64(optional + 24) : r.u32(optional + 28);
		int subsystem = r.u16(optional + 68);
		int dllCharacteristics = r.u16(optional + 70);
		int sectionTable = optional + optionalHeaderSize;

		LinkedHashMap<String, String> details = new LinkedHashMap<>();
		details.put("Machine", peMachine(machine));
		details.put("Subsystem", peSubsystem(subsystem));
		details.put("Image Base", hex(imageBase));
		details.put("Entrypoint RVA", hex(entryPoint));
		details.put("Sections", Integer.toString(numberOfSections));
		details.put("Timestamp", formatTimestamp(timestamp));
		details.put("ASLR", hasFlag(dllCharacteristics, 0x0040) ? "Enabled" : "No");
		details.put("NX", hasFlag(dllCharacteristics, 0x0100) ? "Enabled" : "No");
		details.put("Large Address Aware", hasFlag(characteristics, 0x0020) ? "Yes" : "No");
		details.put("Debug Stripped", hasFlag(characteristics, 0x0200) ? "Yes" : "No");

		List<ExecutableTableEntry> entries = new ArrayList<>();
		for (int i = 0; i < numberOfSections; i++) {
			int offset = sectionTable + (i * 40);
			r.requireRange(offset, 40, "PE section table is truncated");
			String name = r.nullTerminatedAscii(offset, 8);
			long virtualAddress = r.u32(offset + 12);
			long rawSize = r.u32(offset + 16);
			long rawOffset = r.u32(offset + 20);
			long sectionFlags = r.u32(offset + 36);
			entries.add(new ExecutableTableEntry(
					name.isBlank() ? "#" + (i + 1) : name,
					virtualAddress,
					rawOffset,
					rawSize,
					peSectionFlags(sectionFlags)));
		}

		return ExecutableFileInfo.builder()
				.format("PE")
				.fileType(hasFlag(characteristics, 0x2000) ? "Dynamic-link library" : "Executable image")
				.platform("Windows")
				.architecture(peMachine(machine))
				.bitness(is64 ? "64-bit" : "32-bit")
				.endianness("Little-endian")
				.entriesTitle("Sections")
				.details(details)
				.entries(entries)
				.build();
	}

	private static ExecutableFileInfo parseElf(byte[] data) throws ExecutableParseException {
		boolean is64 = (data[4] & 0xFF) == 2;
		boolean littleEndian = (data[5] & 0xFF) != 2;
		BinaryReader r = littleEndian ? BinaryReader.littleEndian(data) : BinaryReader.bigEndian(data);

		int type = r.u16(16);
		int machine = r.u16(18);
		long entry = is64 ? r.u64(24) : r.u32(24);
		long phoff = is64 ? r.u64(32) : r.u32(28);
		long shoff = is64 ? r.u64(40) : r.u32(32);
		int phentsize = r.u16(is64 ? 54 : 42);
		int phnum = r.u16(is64 ? 56 : 44);
		int shentsize = r.u16(is64 ? 58 : 46);
		int shnum = r.u16(is64 ? 60 : 48);
		int shstrndx = r.u16(is64 ? 62 : 50);

		String interpreter = null;
		boolean dynamic = false;
		for (int i = 0; i < phnum; i++) {
			int off = Math.toIntExact(phoff + ((long) i * phentsize));
			r.requireRange(off, phentsize, "ELF program header table is truncated");
			long pType = r.u32(off);
			long pOffset = is64 ? r.u64(off + 8) : r.u32(off + 4);
			long pFilesz = is64 ? r.u64(off + 32) : r.u32(off + 16);
			if (pType == 3) {
				interpreter = r.utf8(Math.toIntExact(pOffset), Math.toIntExact(pFilesz));
			} else if (pType == 2) {
				dynamic = true;
			}
		}

		byte[] names = new byte[0];
		if (shnum > 0 && shstrndx > 0 && shstrndx < shnum) {
			int shstrOff = Math.toIntExact(shoff + ((long) shstrndx * shentsize));
			r.requireRange(shstrOff, shentsize, "ELF string table header is truncated");
			long tableOffset = is64 ? r.u64(shstrOff + 24) : r.u32(shstrOff + 16);
			long tableSize = is64 ? r.u64(shstrOff + 32) : r.u32(shstrOff + 20);
			r.requireRange(Math.toIntExact(tableOffset), Math.toIntExact(tableSize), "ELF section string table is truncated");
			names = r.slice(Math.toIntExact(tableOffset), Math.toIntExact(tableSize));
		}

		boolean stripped = true;
		List<ExecutableTableEntry> entries = new ArrayList<>();
		for (int i = 0; i < shnum; i++) {
			int off = Math.toIntExact(shoff + ((long) i * shentsize));
			r.requireRange(off, shentsize, "ELF section table is truncated");
			int nameIndex = (int) r.u32(off);
			String name = readElfString(names, nameIndex);
			long flags = is64 ? r.u64(off + 8) : r.u32(off + 8);
			long addr = is64 ? r.u64(off + 16) : r.u32(off + 12);
			long fileOffset = is64 ? r.u64(off + 24) : r.u32(off + 16);
			long size = is64 ? r.u64(off + 32) : r.u32(off + 20);
			if (".symtab".equals(name)) {
				stripped = false;
			}
			if (!name.isBlank()) {
				entries.add(new ExecutableTableEntry(name, addr, fileOffset, size, elfSectionFlags(flags)));
			}
		}

		LinkedHashMap<String, String> details = new LinkedHashMap<>();
		details.put("Machine", elfMachine(machine));
		details.put("OS ABI", elfOsAbi(data[7] & 0xFF));
		details.put("ABI Version", Integer.toString(data[8] & 0xFF));
		details.put("Entrypoint", hex(entry));
		details.put("Program Headers", Integer.toString(phnum));
		details.put("Sections", Integer.toString(shnum));
		details.put("Dynamic Linking", dynamic ? "Yes" : "No");
		details.put("Position Independent", type == 3 ? "Yes" : "No");
		details.put("Stripped", stripped ? "Likely" : "No");
		if (interpreter != null && !interpreter.isBlank()) {
			details.put("Interpreter", interpreter);
		}

		return ExecutableFileInfo.builder()
				.format("ELF")
				.fileType(elfType(type))
				.platform("Linux / Unix")
				.architecture(elfMachine(machine))
				.bitness(is64 ? "64-bit" : "32-bit")
				.endianness(littleEndian ? "Little-endian" : "Big-endian")
				.entriesTitle("Sections")
				.details(details)
				.entries(entries)
				.build();
	}

	private static ExecutableFileInfo parseMachO(byte[] data) throws ExecutableParseException {
		int magic = intBigEndian(data, 0);
		boolean littleEndian = magic == 0xCEFAEDFE || magic == 0xCFFAEDFE;
		boolean is64 = magic == 0xFEEDFACF || magic == 0xCFFAEDFE;
		BinaryReader r = littleEndian ? BinaryReader.littleEndian(data) : BinaryReader.bigEndian(data);

		int cpuType = r.s32(4);
		int fileType = r.s32(12);
		int ncmds = r.s32(16);
		int flags = r.s32(24);
		int cursor = is64 ? 32 : 28;

		long entryPoint = -1;
		List<ExecutableTableEntry> entries = new ArrayList<>();
		for (int i = 0; i < ncmds; i++) {
			r.requireRange(cursor, 8, "Mach-O load command table is truncated");
			int command = r.s32(cursor);
			int commandSize = r.s32(cursor + 4);
			if (commandSize < 8) {
				throw new ExecutableParseException("Invalid Mach-O load command size.");
			}
			r.requireRange(cursor, commandSize, "Mach-O load command exceeds file size");
			if (command == (is64 ? 0x19 : 0x1)) {
				int sectionCount = r.s32(cursor + (is64 ? 64 : 48));
				int sectionOffset = cursor + (is64 ? 72 : 56);
				int sectionSize = is64 ? 80 : 68;
				for (int s = 0; s < sectionCount; s++) {
					int sectionCursor = sectionOffset + (s * sectionSize);
					r.requireRange(sectionCursor, sectionSize, "Mach-O section table is truncated");
					String sectName = r.nullTerminatedAscii(sectionCursor, 16);
					String segName = r.nullTerminatedAscii(sectionCursor + 16, 16);
					long addr = is64 ? r.u64(sectionCursor + 32) : r.u32(sectionCursor + 32);
					long size = is64 ? r.u64(sectionCursor + 40) : r.u32(sectionCursor + 36);
					long offset = is64 ? r.u32(sectionCursor + 48) : r.u32(sectionCursor + 40);
					entries.add(new ExecutableTableEntry(
							(segName + ":" + sectName).replaceFirst("^:", ""),
							addr,
							offset,
							size,
							segName));
				}
			} else if (command == 0x80000028) {
				entryPoint = r.u64(cursor + 8);
			}
			cursor += commandSize;
		}

		LinkedHashMap<String, String> details = new LinkedHashMap<>();
		details.put("CPU Type", machCpuType(cpuType));
		details.put("Load Commands", Integer.toString(ncmds));
		details.put("Flags", machFlags(flags));
		if (entryPoint >= 0) {
			details.put("Entrypoint Offset", hex(entryPoint));
		}
		details.put("Position Independent", (flags & 0x200000) != 0 ? "Yes" : "No");

		return ExecutableFileInfo.builder()
				.format("Mach-O")
				.fileType(machFileType(fileType))
				.platform("macOS")
				.architecture(machCpuType(cpuType))
				.bitness(is64 ? "64-bit" : "32-bit")
				.endianness(littleEndian ? "Little-endian" : "Big-endian")
				.entriesTitle("Sections")
				.details(details)
				.entries(entries)
				.build();
	}

	private static ExecutableFileInfo parseFatMachO(byte[] data) throws ExecutableParseException {
		int magic = intBigEndian(data, 0);
		boolean littleEndian = magic == FAT_CIGAM || magic == FAT_CIGAM_64;
		boolean is64 = magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
		BinaryReader r = littleEndian ? BinaryReader.littleEndian(data) : BinaryReader.bigEndian(data);
		int count = r.s32(4);
		int entrySize = is64 ? 32 : 20;

		List<ExecutableTableEntry> entries = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			int off = 8 + (i * entrySize);
			r.requireRange(off, entrySize, "Mach-O fat header is truncated");
			int cpuType = r.s32(off);
			long offset = is64 ? r.u64(off + 8) : r.u32(off + 8);
			long size = is64 ? r.u64(off + 16) : r.u32(off + 12);
			long align = is64 ? r.u32(off + 24) : r.u32(off + 16);
			entries.add(new ExecutableTableEntry(
					machCpuType(cpuType),
					-1,
					offset,
					size,
					"align 2^" + align));
		}

		LinkedHashMap<String, String> details = new LinkedHashMap<>();
		details.put("Slices", Integer.toString(count));
		details.put("Container", is64 ? "Fat Mach-O 64" : "Fat Mach-O");

		return ExecutableFileInfo.builder()
				.format("Mach-O (Universal)")
				.fileType("Fat binary")
				.platform("macOS")
				.architecture("Multi-architecture")
				.bitness(is64 ? "64-bit offsets" : "32-bit offsets")
				.endianness(littleEndian ? "Little-endian" : "Big-endian")
				.entriesTitle("Architectures")
				.details(details)
				.entries(entries)
				.note("Contained slices are listed without parsing each inner Mach-O image.")
				.build();
	}

	private static boolean isPe(byte[] data) {
		return data.length >= 64 && data[0] == 'M' && data[1] == 'Z';
	}

	private static boolean isElf(byte[] data) {
		return data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
	}

	private static boolean isMachO(byte[] data) {
		int magic = intBigEndian(data, 0);
		return magic == 0xFEEDFACE || magic == 0xCEFAEDFE || magic == 0xFEEDFACF || magic == 0xCFFAEDFE;
	}

	private static boolean isFatMachO(byte[] data) {
		int magic = intBigEndian(data, 0);
		return magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
	}

	private static int intBigEndian(byte[] data, int offset) {
		return ((data[offset] & 0xFF) << 24)
				| ((data[offset + 1] & 0xFF) << 16)
				| ((data[offset + 2] & 0xFF) << 8)
				| (data[offset + 3] & 0xFF);
	}

	private static boolean hasFlag(int value, int flag) {
		return (value & flag) != 0;
	}

	private static String suffix(String fileName) {
		return fileName == null || fileName.isBlank() ? "" : " for " + fileName;
	}

	private static String readElfString(byte[] table, int offset) {
		if (offset < 0 || offset >= table.length) {
			return "";
		}
		int end = offset;
		while (end < table.length && table[end] != 0) {
			end++;
		}
		return new String(table, offset, end - offset, StandardCharsets.UTF_8);
	}

	private static String formatTimestamp(long epochSeconds) {
		if (epochSeconds <= 0) {
			return "Unknown";
		}
		return java.time.Instant.ofEpochSecond(epochSeconds).toString();
	}

	private static String hex(long value) {
		return "0x" + Long.toUnsignedString(value, 16).toUpperCase(Locale.ROOT);
	}

	private static String peMachine(int machine) {
		return switch (machine) {
			case 0x014C -> "x86";
			case 0x8664 -> "x86-64";
			case 0x01C0 -> "ARM";
			case 0xAA64 -> "ARM64";
			case 0x0200 -> "IA-64";
			default -> "Machine 0x" + Integer.toHexString(machine).toUpperCase(Locale.ROOT);
		};
	}

	private static String peSubsystem(int subsystem) {
		return switch (subsystem) {
			case 2 -> "Windows GUI";
			case 3 -> "Windows CUI";
			case 5 -> "OS/2 CUI";
			case 7 -> "POSIX CUI";
			case 9 -> "Windows CE GUI";
			case 10 -> "EFI Application";
			case 11 -> "EFI Boot Service Driver";
			case 12 -> "EFI Runtime Driver";
			case 13 -> "EFI ROM";
			case 14 -> "Xbox";
			case 16 -> "Windows Boot Application";
			default -> "Subsystem " + subsystem;
		};
	}

	private static String peSectionFlags(long flags) {
		List<String> values = new ArrayList<>();
		if ((flags & 0x20000000L) != 0) {
			values.add("execute");
		}
		if ((flags & 0x40000000L) != 0) {
			values.add("read");
		}
		if ((flags & 0x80000000L) != 0) {
			values.add("write");
		}
		return values.isEmpty() ? hex(flags) : String.join(", ", values);
	}

	private static String elfType(int type) {
		return switch (type) {
			case 1 -> "Relocatable";
			case 2 -> "Executable";
			case 3 -> "Shared object";
			case 4 -> "Core";
			default -> "Type " + type;
		};
	}

	private static String elfMachine(int machine) {
		return switch (machine) {
			case 0x03 -> "x86";
			case 0x3E -> "x86-64";
			case 0x28 -> "ARM";
			case 0xB7 -> "ARM64";
			case 0x08 -> "MIPS";
			case 0x14 -> "PowerPC";
			case 0x15 -> "PowerPC64";
			case 0xF3 -> "RISC-V";
			default -> "Machine " + machine;
		};
	}

	private static String elfOsAbi(int abi) {
		return switch (abi) {
			case 0 -> "System V";
			case 1 -> "HP-UX";
			case 2 -> "NetBSD";
			case 3 -> "Linux";
			case 6 -> "Solaris";
			case 9 -> "FreeBSD";
			case 12 -> "OpenBSD";
			default -> "ABI " + abi;
		};
	}

	private static String elfSectionFlags(long flags) {
		List<String> values = new ArrayList<>();
		if ((flags & 0x1) != 0) {
			values.add("write");
		}
		if ((flags & 0x2) != 0) {
			values.add("alloc");
		}
		if ((flags & 0x4) != 0) {
			values.add("exec");
		}
		return values.isEmpty() ? hex(flags) : String.join(", ", values);
	}

	private static String machCpuType(int cpuType) {
		int arch = cpuType & 0x00FFFFFF;
		boolean is64 = (cpuType & 0x01000000) != 0;
		return switch (arch) {
			case 7 -> is64 ? "x86-64" : "x86";
			case 12 -> is64 ? "ARM64" : "ARM";
			case 18 -> "PowerPC";
			default -> "CPU " + cpuType;
		};
	}

	private static String machFileType(int fileType) {
		return switch (fileType) {
			case 1 -> "Object";
			case 2 -> "Executable";
			case 3 -> "Fixed VM library";
			case 4 -> "Core";
			case 5 -> "Preloaded executable";
			case 6 -> "Dynamic library";
			case 7 -> "Dynamic linker";
			case 8 -> "Bundle";
			default -> "Type " + fileType;
		};
	}

	private static String machFlags(int flags) {
		List<String> values = new ArrayList<>();
		if ((flags & 0x1) != 0) {
			values.add("noundefs");
		}
		if ((flags & 0x4) != 0) {
			values.add("dyldlink");
		}
		if ((flags & 0x2000) != 0) {
			values.add("twolevel");
		}
		if ((flags & 0x200000) != 0) {
			values.add("pie");
		}
		return values.isEmpty() ? "None" : String.join(", ", values);
	}

	private static final class BinaryReader {
		private final byte[] data;
		private final boolean littleEndian;

		private BinaryReader(byte[] data, boolean littleEndian) {
			this.data = data;
			this.littleEndian = littleEndian;
		}

		static BinaryReader littleEndian(byte[] data) {
			return new BinaryReader(data, true);
		}

		static BinaryReader bigEndian(byte[] data) {
			return new BinaryReader(data, false);
		}

		void requireRange(int offset, int length, String message) throws ExecutableParseException {
			if (offset < 0 || length < 0 || offset + length > data.length) {
				throw new ExecutableParseException(message + ".");
			}
		}

		int u16(int offset) throws ExecutableParseException {
			requireRange(offset, 2, "Unexpected end of file");
			if (littleEndian) {
				return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
			}
			return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
		}

		int s32(int offset) throws ExecutableParseException {
			return (int) u32(offset);
		}

		long u32(int offset) throws ExecutableParseException {
			requireRange(offset, 4, "Unexpected end of file");
			if (littleEndian) {
				return ((long) data[offset] & 0xFF)
						| (((long) data[offset + 1] & 0xFF) << 8)
						| (((long) data[offset + 2] & 0xFF) << 16)
						| (((long) data[offset + 3] & 0xFF) << 24);
			}
			return (((long) data[offset] & 0xFF) << 24)
					| (((long) data[offset + 1] & 0xFF) << 16)
					| (((long) data[offset + 2] & 0xFF) << 8)
					| ((long) data[offset + 3] & 0xFF);
		}

		long u64(int offset) throws ExecutableParseException {
			requireRange(offset, 8, "Unexpected end of file");
			long low;
			long high;
			if (littleEndian) {
				low = u32(offset);
				high = u32(offset + 4);
			} else {
				high = u32(offset);
				low = u32(offset + 4);
			}
			return (high << 32) | low;
		}

		String nullTerminatedAscii(int offset, int maxLength) throws ExecutableParseException {
			requireRange(offset, maxLength, "Unexpected end of file");
			int end = offset;
			while (end < offset + maxLength && data[end] != 0) {
				end++;
			}
			return new String(data, offset, end - offset, StandardCharsets.US_ASCII).trim();
		}

		String utf8(int offset, int maxLength) throws ExecutableParseException {
			requireRange(offset, maxLength, "Unexpected end of file");
			int end = offset;
			while (end < offset + maxLength && data[end] != 0) {
				end++;
			}
			return new String(data, offset, end - offset, StandardCharsets.UTF_8);
		}

		byte[] slice(int offset, int length) throws ExecutableParseException {
			requireRange(offset, length, "Unexpected end of file");
			byte[] out = new byte[length];
			System.arraycopy(data, offset, out, 0, length);
			return out;
		}
	}
}
