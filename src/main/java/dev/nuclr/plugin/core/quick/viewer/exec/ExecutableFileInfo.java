package dev.nuclr.plugin.core.quick.viewer.exec;

import java.util.LinkedHashMap;
import java.util.List;

import lombok.Builder;
import lombok.Singular;
import lombok.Value;

@Value
@Builder
public class ExecutableFileInfo {
	String format;
	String fileType;
	String platform;
	String architecture;
	String bitness;
	String endianness;
	String entriesTitle;
	@Builder.Default
	LinkedHashMap<String, String> details = new LinkedHashMap<>();
	@Singular
	List<ExecutableTableEntry> entries;
	@Singular
	List<String> notes;
}
