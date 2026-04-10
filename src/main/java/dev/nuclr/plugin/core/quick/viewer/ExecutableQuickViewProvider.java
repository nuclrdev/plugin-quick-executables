package dev.nuclr.plugin.core.quick.viewer;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JComponent;

import dev.nuclr.platform.NuclrThemeScheme;
import dev.nuclr.platform.plugin.NuclrPlugin;
import dev.nuclr.platform.plugin.NuclrPluginContext;
import dev.nuclr.platform.plugin.NuclrResourcePath;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ExecutableQuickViewProvider implements NuclrPlugin {

	private static final Set<String> SUPPORTED_EXTENSIONS = Set.of(
			"exe", "dll", "sys", "ocx",
			"so", "bin", "run", "appimage",
			"dylib", "mach", "bundle", "o", "a");

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
	public void load(NuclrPluginContext ctx) {
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
		if (mimeType == null) {
			return false;
		}
		String lowered = mimeType.toLowerCase(Locale.ROOT);
		return lowered.contains("executable")
				|| lowered.contains("elf")
				|| lowered.contains("mach")
				|| lowered.contains("dosexec")
				|| lowered.contains("x-msdownload");
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
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String docUrl() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Developer type() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void updateTheme(NuclrThemeScheme themeScheme) {
		// TODO Auto-generated method stub
		
	}
}
