package dev.nuclr.plugin.core.quick.viewer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JComponent;

import org.apache.commons.io.FilenameUtils;

import dev.nuclr.platform.NuclrThemeScheme;
import dev.nuclr.platform.plugin.NuclrPluginContext;
import dev.nuclr.platform.plugin.NuclrResource;
import dev.nuclr.platform.plugin.QuickViewNuclrPlugin;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ExecutableQuickViewProvider implements QuickViewNuclrPlugin {
	private static final int MACH_O_MAGIC = 0xFEEDFACE;
	private static final int MACH_O_CIGAM = 0xCEFAEDFE;
	private static final int MACH_O_MAGIC_64 = 0xFEEDFACF;
	private static final int MACH_O_CIGAM_64 = 0xCFFAEDFE;
	private static final int FAT_MAGIC = 0xCAFEBABE;
	private static final int FAT_CIGAM = 0xBEBAFECA;
	private static final int FAT_MAGIC_64 = 0xCAFEBABF;
	private static final int FAT_CIGAM_64 = 0xBFBAFECA;

	private String uuid = UUID.randomUUID().toString();

	private static final Set<String> SUPPORTED_EXTENSIONS = Set.of("exe", "dll", "sys", "ocx", "so", "bin", "run",
			"appimage", "dylib", "mach", "bundle", "o", "a");

	private NuclrPluginContext context;
	private ExecutableViewPanel panel;
	private volatile AtomicBoolean currentCancelled;

	@Override
	public JComponent panel() {
		if (panel == null) {
			panel = new ExecutableViewPanel();
		}
		return panel;
	}

	@Override
	public void preinit(NuclrPluginContext ctx) {
		this.context = ctx;
	}

	@Override
	public void init() {
	}

	@Override
	public NuclrPluginContext getContext() {
		return this.context;
	}

	@Override
	public boolean supports(NuclrResource resource) {
		if (resource == null) {
			return false;
		}
		String extension = extension(resource);
		if (extension != null && !extension.isBlank()) {
			return SUPPORTED_EXTENSIONS.contains(extension.toLowerCase(Locale.ROOT));
		}
		try {
			return hasRecognizedExecutableHeader(resource);
		} catch (Exception e) {
			log.error("Failed to check executable header for {}: {}", resource, e.getMessage());
			return false;
		}
	}

	private static String extension(Path path) {
		var name = path.getFileName() != null ? path.getFileName().toString() : path.toString();
		return FilenameUtils.getExtension(name);
	}

	private static String extension(NuclrResource resource) {
		String name = resource.getName();
		if ((name == null || name.isBlank()) && resource.getPath() != null
				&& resource.getPath().getFileName() != null) {
			name = resource.getPath().getFileName().toString();
		}
		if (name == null) {
			return null;
		}
		int dot = name.lastIndexOf('.');
		return dot > 0 ? name.substring(dot + 1) : null;
	}

	private static boolean hasRecognizedExecutableHeader(NuclrResource resource) throws Exception {
		
		if (resource == null || resource.isFolder() || false == resource.isReadable() || resource.getPath() == null) {
			return false;
		}
		
		try (var in = resource.openInputStream()) {
			byte[] header = in.readNBytes(4);
			if (header.length < 4) {
				return false;
			}
			if (header[0] == 'M' && header[1] == 'Z') {
				return true;
			}
			if ((header[0] & 0xFF) == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F') {
				return true;
			}
			int magic = ((header[0] & 0xFF) << 24)
					| ((header[1] & 0xFF) << 16)
					| ((header[2] & 0xFF) << 8)
					| (header[3] & 0xFF);
			return magic == MACH_O_MAGIC
					|| magic == MACH_O_CIGAM
					|| magic == MACH_O_MAGIC_64
					|| magic == MACH_O_CIGAM_64
					|| magic == FAT_MAGIC
					|| magic == FAT_CIGAM
					|| magic == FAT_MAGIC_64
					|| magic == FAT_CIGAM_64;
		} catch (IOException e) {
			log.debug("Unable to inspect executable header for {}", resource, e);
			return false;
		}
	}

	@Override
	public boolean openResource(NuclrResource resource, AtomicBoolean cancelled) {
		if (currentCancelled != null) {
			currentCancelled.set(true);
		}
		currentCancelled = cancelled;
		panel();
		return panel.load(resource, cancelled);
	}

	@Override
	public void closeResource() {
		if (currentCancelled != null) {
			currentCancelled.set(true);
			currentCancelled = null;
		}
		if (panel != null) {
			panel.clear();
		}
	}

	@Override
	public void unload() {
		closeResource();
		panel = null;
		context = null;
	}

	@Override
	public int priority() {
		return 1;
	}

	@Override
	public boolean onFocusGained() {
		return false;
	}

	@Override
	public void onFocusLost() {
	}

	@Override
	public boolean isFocused() {
		return false;
	}

	private String name = "Executable Quick Viewer";
	private String id = "dev.nuclr.plugin.core.quickviewer.executables";
	private final String version = loadVersion();
	private String description = "A quick viewer for PE, ELF and Mach-O executables and libraries.";
	private String author = "Nuclr Development Team";
	private String license = "Apache-2.0";
	private String website = "https://nuclr.dev";
	private String pageUrl = "https://nuclr.dev/plugins/core/executable-quick-viewer.html";
	private String docUrl = "https://nuclr.dev/plugins/core/executable-quick-viewer.html";

	@Override
	public String id() {
		return id;
	}

	@Override
	public String name() {
		return name;
	}

	@Override
	public String version() {
		return version;
	}
	private static String loadVersion() {
		try (var stream = ExecutableQuickViewProvider.class.getResourceAsStream("/plugin.properties")) {
			if (stream == null) return "unknown";
			var props = new java.util.Properties();
			props.load(stream);
			return props.getProperty("version", "unknown");
		} catch (java.io.IOException e) {
			return "unknown";
		}
	}

	@Override
	public String description() {
		return description;
	}

	@Override
	public String author() {
		return author;
	}

	@Override
	public String license() {
		return license;
	}

	@Override
	public String website() {
		return null;
	}

	@Override
	public String pageUrl() {
		return pageUrl;
	}

	@Override
	public String docUrl() {
		return docUrl;
	}

	@Override
	public Developer developer() {
		return Developer.Official;
	}

	@Override
	public void updateTheme(NuclrThemeScheme themeScheme) {
	}

	@Override
	public NuclrResource getCurrentResource() {
		return null;
	}

	@Override
	public String uuid() {
		return uuid;
	}

}
