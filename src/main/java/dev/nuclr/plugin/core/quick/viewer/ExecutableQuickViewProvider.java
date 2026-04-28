package dev.nuclr.plugin.core.quick.viewer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JComponent;

import dev.nuclr.platform.NuclrThemeScheme;
import dev.nuclr.platform.plugin.NuclrPlugin;
import dev.nuclr.platform.plugin.NuclrPluginContext;
import dev.nuclr.platform.plugin.NuclrPluginRole;
import dev.nuclr.platform.plugin.NuclrResourcePath;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ExecutableQuickViewProvider implements NuclrPlugin {
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
	public void load(NuclrPluginContext ctx, boolean isTemplate) {
		this.context = ctx;
	}

	@Override
	public boolean supports(NuclrResourcePath resource) {
		if (resource == null) {
			return false;
		}
		String extension = resource.getExtension();
		if (extension != null && !extension.isBlank()) {
			return SUPPORTED_EXTENSIONS.contains(extension.toLowerCase(Locale.ROOT));
		}
		String mimeType = resource.getMimeType();
		if (mimeType != null) {
			String lowered = mimeType.toLowerCase(Locale.ROOT);
			if (lowered.contains("executable") || lowered.contains("elf") || lowered.contains("mach")
					|| lowered.contains("dosexec") || lowered.contains("x-msdownload")) {
				return true;
			}
		}
		return hasRecognizedExecutableHeader(resource.getPath());
	}

	private static boolean hasRecognizedExecutableHeader(Path path) {
		if (path == null || !Files.isRegularFile(path) || !Files.isReadable(path)) {
			return false;
		}
		try (InputStream in = Files.newInputStream(path)) {
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
			log.debug("Unable to inspect executable header for {}", path, e);
			return false;
		}
	}

	@Override
	public boolean openResource(NuclrResourcePath resource, AtomicBoolean cancelled) {
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
	private String version = "1.0.0";
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
	public Developer type() {
		return Developer.Official;
	}

	@Override
	public void updateTheme(NuclrThemeScheme themeScheme) {
	}

	@Override
	public NuclrPluginRole role() {
		return NuclrPluginRole.QuickViewer;
	}

	@Override
	public NuclrResourcePath getCurrentResource() {
		return null;
	}

	@Override
	public String uuid() {
		return uuid;
	}

}
