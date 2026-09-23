package dev.nuclr.plugin.core.quick.viewer;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JComponent;

import org.apache.commons.io.FilenameUtils;

import dev.nuclr.platform.NuclrThemeScheme;
import dev.nuclr.platform.plugin.NuclrPluginContext;
import dev.nuclr.platform.plugin.NuclrResource;
import dev.nuclr.platform.plugin.QuickViewNuclrPlugin;
import dev.nuclr.plugin.core.quick.viewer.exec.ExecutableFileInfo;
import dev.nuclr.plugin.core.quick.viewer.exec.ExecutableParser;
import dev.nuclr.plugin.core.quick.viewer.exec.ExecutableTableEntry;
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
		if (resource == null || resource.isFolder() || !resource.isReadable()) {
			return false;
		}
		String extension = extension(resource);
		if (extension != null && !extension.isBlank()) {
			return SUPPORTED_EXTENSIONS.contains(extension.toLowerCase(Locale.ROOT));
		}
		// Reading the header means opening the resource, and for one with no local file that
		// can mean fetching the whole object just to see its first four bytes. Selection runs
		// on every cursor move, so extension-less remote resources are left alone.
		if (resource.getPath() == null) {
			return false;
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

	/** Headers, sections and tables all sit well inside this for the binaries worth drawing. */
	private static final int MAX_THUMBNAIL_BYTES = 64 * 1024 * 1024;

	@Override
	public boolean supportsThumbnails() {
		return true;
	}

	/** A header page: format and target, the key header fields, then the section table. */
	@Override
	public BufferedImage thumbnail(NuclrResource resource, int maxWidth, int maxHeight, AtomicBoolean cancelled) {
		if (maxWidth <= 0 || maxHeight <= 0 || !supports(resource)) {
			return null;
		}
		try {
			byte[] data;
			try (var in = resource.openInputStream()) {
				data = in.readNBytes(MAX_THUMBNAIL_BYTES);
			}
			if (cancelled != null && cancelled.get()) {
				return null;
			}
			ExecutableFileInfo info = ExecutableParser.parse(resource.getName(), data);
			List<PageThumbnail.Line> lines = new ArrayList<>();
			lines.add(PageThumbnail.Line.title(info.getFormat()));
			lines.add(PageThumbnail.Line.muted(Stream.of(info.getFileType(), info.getPlatform(),
					info.getArchitecture(), info.getBitness())
					.filter(Objects::nonNull).filter(value -> !value.isBlank())
					.collect(Collectors.joining(" · "))));
			lines.add(PageThumbnail.Line.blank());
			for (Map.Entry<String, String> detail : info.getDetails().entrySet()) {
				lines.add(PageThumbnail.Line.text(detail.getKey() + ": " + detail.getValue()));
			}
			if (!info.getEntries().isEmpty()) {
				lines.add(PageThumbnail.Line.heading(info.getEntriesTitle() != null ? info.getEntriesTitle() : "Entries"));
				info.getEntries().stream().limit(100).map(ExecutableTableEntry::getName)
						.forEach(name -> lines.add(PageThumbnail.Line.mono(name)));
			}
			return PageThumbnail.render(lines, maxWidth, maxHeight, cancelled);
		} catch (Exception e) {
			log.debug("No thumbnail for {}: {}", resource.getName(), e.toString());
			return null;
		}
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
