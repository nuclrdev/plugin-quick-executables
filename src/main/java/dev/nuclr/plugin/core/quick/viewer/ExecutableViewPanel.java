package dev.nuclr.plugin.core.quick.viewer;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.Border;

import dev.nuclr.platform.plugin.NuclrResourcePath;
import dev.nuclr.plugin.core.quick.viewer.exec.ExecutableFileInfo;
import dev.nuclr.plugin.core.quick.viewer.exec.ExecutableParser;
import dev.nuclr.plugin.core.quick.viewer.exec.ExecutableTableEntry;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ExecutableViewPanel extends JPanel {

	private static final Font MONO_SMALL = new Font(Font.MONOSPACED, Font.PLAIN, 11);

	private volatile Thread loadThread;

	public ExecutableViewPanel() {
		setLayout(new BorderLayout());
		showMessage("No file selected.");
	}

	public boolean load(NuclrResourcePath item, AtomicBoolean cancelled) {
		Thread prev = loadThread;
		if (prev != null) {
			prev.interrupt();
		}
		showMessage("Loading...");
		loadThread = Thread.ofVirtual().start(() -> {
			try {
				byte[] data;
				try (var in = item.openStream()) {
					data = in.readAllBytes();
				}
				if (cancelled.get()) {
					return;
				}
				ExecutableFileInfo info = ExecutableParser.parse(item.getName(), data);
				if (cancelled.get()) {
					return;
				}
				SwingUtilities.invokeLater(() -> showInfo(item, info));
			} catch (Exception e) {
				if (cancelled.get()) {
					return;
				}
				log.error("Failed to parse executable: {}", item.getName(), e);
				String msg = e.getMessage();
				if (msg == null || msg.isBlank()) {
					msg = e.getClass().getSimpleName();
				}
				if (msg.length() > 300) {
					msg = msg.substring(0, 300) + "...";
				}
				String finalMsg = msg;
				SwingUtilities.invokeLater(() -> showError(finalMsg));
			}
		});
		return true;
	}

	public void clear() {
		Thread prev = loadThread;
		if (prev != null) {
			prev.interrupt();
		}
		loadThread = null;
		SwingUtilities.invokeLater(() -> showMessage(""));
	}

	private void showMessage(String text) {
		removeAll();
		add(new JLabel(text, JLabel.CENTER), BorderLayout.CENTER);
		revalidate();
		repaint();
	}

	private void showError(String message) {
		removeAll();
		JPanel errPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.insets = new Insets(4, 0, 4, 0);

		JLabel title = new JLabel("Unsupported or invalid executable");
		title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
		gbc.gridy = 0;
		errPanel.add(title, gbc);

		JLabel detail = new JLabel("<html><center>" + escapeHtml(message) + "</center></html>");
		detail.setForeground(UIManager.getColor("Label.disabledForeground"));
		gbc.gridy = 1;
		errPanel.add(detail, gbc);

		add(errPanel, BorderLayout.CENTER);
		revalidate();
		repaint();
	}

	private void showInfo(NuclrResourcePath item, ExecutableFileInfo info) {
		removeAll();
		JPanel content = buildContent(item, info);
		JScrollPane scroll = new JScrollPane(
				content,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scroll.setBorder(null);
		scroll.getVerticalScrollBar().setUnitIncrement(16);
		add(scroll, BorderLayout.CENTER);
		SwingUtilities.invokeLater(() -> scroll.getVerticalScrollBar().setValue(0));
		revalidate();
		repaint();
	}

	private JPanel buildContent(NuclrResourcePath item, ExecutableFileInfo info) {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

		FormSection summary = new FormSection("Summary");
		summary.addRow("Name", item.getName());
		summary.addRow("File size", formatSize(item.getSizeBytes()));
		summary.addRow("Format", info.getFormat());
		summary.addRow("Type", info.getFileType());
		summary.addRow("Architecture", info.getArchitecture());
		summary.addRow("Bitness", info.getBitness());
		summary.addRow("Endianness", info.getEndianness());
		if (info.getPlatform() != null) {
			summary.addRow("Platform", info.getPlatform());
		}
		panel.add(summary);
		panel.add(vgap(6));

		if (!info.getDetails().isEmpty()) {
			FormSection detailSection = new FormSection("Details");
			for (Map.Entry<String, String> entry : info.getDetails().entrySet()) {
				detailSection.addRow(entry.getKey(), entry.getValue());
			}
			panel.add(detailSection);
			panel.add(vgap(6));
		}

		if (!info.getNotes().isEmpty()) {
			FormSection notesSection = new FormSection("Notes");
			for (String note : info.getNotes()) {
				notesSection.addMonoText(note);
			}
			panel.add(notesSection);
			panel.add(vgap(6));
		}

		if (!info.getEntries().isEmpty()) {
			FormSection tableSection = new FormSection(info.getEntriesTitle());
			for (ExecutableTableEntry entry : info.getEntries()) {
				tableSection.addTableRow(entry.getName(), entry.describe(), formatSize(entry.getSize()));
			}
			panel.add(tableSection);
			panel.add(vgap(6));
		}

		panel.add(Box.createVerticalGlue());
		return panel;
	}

	static String formatSize(long bytes) {
		if (bytes < 0) {
			return "Unknown";
		}
		if (bytes < 1024) {
			return bytes + " B";
		}
		double kb = bytes / 1024.0;
		if (kb < 1024) {
			return String.format("%.1f KB", kb);
		}
		double mb = kb / 1024.0;
		if (mb < 1024) {
			return String.format("%.1f MB", mb);
		}
		double gb = mb / 1024.0;
		if (gb < 1024) {
			return String.format("%.2f GB", gb);
		}
		return String.format("%.2f TB", gb / 1024.0);
	}

	static String escapeHtml(String s) {
		if (s == null) {
			return "";
		}
		return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
	}

	private static Component vgap(int height) {
		return Box.createVerticalStrut(height);
	}

	private static class FormSection extends JPanel {

		private final JPanel grid;
		private int row = 0;

		FormSection(String title) {
			setLayout(new BorderLayout(0, 2));
			setAlignmentX(LEFT_ALIGNMENT);
			setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
			setOpaque(false);

			JLabel header = new JLabel(title);
			header.setFont(header.getFont().deriveFont(Font.BOLD));
			header.setBorder(BorderFactory.createEmptyBorder(0, 0, 3, 0));
			add(header, BorderLayout.NORTH);

			grid = new JPanel(new GridBagLayout());
			grid.setOpaque(false);

			Color borderColor = UIManager.getColor("Separator.foreground");
			if (borderColor == null) {
				borderColor = Color.GRAY;
			}
			Border left = BorderFactory.createMatteBorder(0, 2, 0, 0, borderColor);
			Border pad = BorderFactory.createEmptyBorder(2, 8, 2, 2);
			grid.setBorder(BorderFactory.createCompoundBorder(left, pad));
			add(grid, BorderLayout.CENTER);
		}

		void addRow(String label, String value) {
			if (value == null || value.isBlank()) {
				return;
			}
			GridBagConstraints kc = new GridBagConstraints();
			kc.gridx = 0;
			kc.gridy = row;
			kc.anchor = GridBagConstraints.NORTHWEST;
			kc.insets = new Insets(1, 0, 1, 10);

			GridBagConstraints vc = new GridBagConstraints();
			vc.gridx = 1;
			vc.gridy = row;
			vc.anchor = GridBagConstraints.NORTHWEST;
			vc.fill = GridBagConstraints.HORIZONTAL;
			vc.weightx = 1.0;
			vc.insets = new Insets(1, 0, 1, 0);
			row++;

			JLabel keyLabel = new JLabel(label + ":");
			keyLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
			JLabel valLabel = new JLabel("<html>" + escapeHtml(value) + "</html>");

			grid.add(keyLabel, kc);
			grid.add(valLabel, vc);
		}

		void addMonoText(String text) {
			GridBagConstraints c = span(row++);
			JLabel label = new JLabel(escapeHtml(text));
			label.setFont(MONO_SMALL);
			grid.add(label, c);
		}

		void addTableRow(String primary, String secondary, String size) {
			GridBagConstraints nameC = new GridBagConstraints();
			nameC.gridx = 0;
			nameC.gridy = row;
			nameC.anchor = GridBagConstraints.NORTHWEST;
			nameC.insets = new Insets(1, 0, 1, 8);

			GridBagConstraints descC = new GridBagConstraints();
			descC.gridx = 1;
			descC.gridy = row;
			descC.anchor = GridBagConstraints.NORTHWEST;
			descC.fill = GridBagConstraints.HORIZONTAL;
			descC.weightx = 1.0;
			descC.insets = new Insets(1, 0, 1, 8);

			GridBagConstraints sizeC = new GridBagConstraints();
			sizeC.gridx = 2;
			sizeC.gridy = row;
			sizeC.anchor = GridBagConstraints.NORTHEAST;
			sizeC.insets = new Insets(1, 0, 1, 0);
			row++;

			JLabel nameLabel = new JLabel(escapeHtml(primary));
			nameLabel.setFont(MONO_SMALL);
			JLabel descLabel = new JLabel("<html>" + escapeHtml(secondary) + "</html>");
			descLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
			JLabel sizeLabel = new JLabel(size);
			sizeLabel.setFont(MONO_SMALL);
			sizeLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

			grid.add(nameLabel, nameC);
			grid.add(descLabel, descC);
			grid.add(sizeLabel, sizeC);
		}

		private GridBagConstraints span(int r) {
			GridBagConstraints c = new GridBagConstraints();
			c.gridx = 0;
			c.gridy = r;
			c.gridwidth = 3;
			c.anchor = GridBagConstraints.NORTHWEST;
			c.fill = GridBagConstraints.HORIZONTAL;
			c.weightx = 1.0;
			return c;
		}
	}
}
