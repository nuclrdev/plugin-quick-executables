package dev.nuclr.plugin.core.quick.viewer.exec;

import java.util.ArrayList;
import java.util.List;

import lombok.Value;

@Value
public class ExecutableTableEntry {
	String name;
	long address;
	long offset;
	long size;
	String flags;

	public String describe() {
		List<String> parts = new ArrayList<>();
		if (address >= 0) {
			parts.add("addr " + hex(address));
		}
		if (offset >= 0) {
			parts.add("offset " + hex(offset));
		}
		if (flags != null && !flags.isBlank()) {
			parts.add(flags);
		}
		return String.join(" | ", parts);
	}

	private static String hex(long value) {
		return "0x" + Long.toUnsignedString(value, 16).toUpperCase();
	}
}
