package dev.nuclr.plugin.core.quick.viewer;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.OpenOption;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import dev.nuclr.platform.plugin.NuclrResource;

class ExecutableThumbnailTest {

	private final ExecutableQuickViewProvider provider = new ExecutableQuickViewProvider();

	@Test
	void drawsAHeaderPageWithinTheBoxBeforeInit() {
		assertTrue(provider.supportsThumbnails());

		BufferedImage image = provider.thumbnail(resource("tool.exe", minimalPe()), 120, 120, new AtomicBoolean());

		assertNotNull(image);
		assertTrue(image.getWidth() <= 120 && image.getHeight() <= 120);
	}

	@Test
	void returnsNullForDamagedOrCancelled() {
		byte[] junk = "not an executable".getBytes(StandardCharsets.US_ASCII);
		assertNull(provider.thumbnail(resource("tool.exe", junk), 120, 120, new AtomicBoolean()));
		assertNull(provider.thumbnail(resource("tool.exe", minimalPe()), 120, 120, new AtomicBoolean(true)));
	}

	/** The same 64-bit PE with one .text section that ExecutableParserTest reads. */
	private static byte[] minimalPe() {
		byte[] data = new byte[0x300];
		ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
		data[0] = 'M';
		data[1] = 'Z';
		b.putInt(0x3C, 0x80);
		b.putInt(0x80, 0x00004550);
		b.putShort(0x84, (short) 0x8664);
		b.putShort(0x86, (short) 1);
		b.putInt(0x88, 1_710_000_000);
		b.putShort(0x94, (short) 0xF0);
		b.putShort(0x96, (short) 0x2022);
		b.putShort(0x98, (short) 0x20B);
		b.putInt(0xA8, 0x1234);
		b.putLong(0xB0, 0x140000000L);
		b.putShort(0xDC, (short) 2);
		b.putShort(0xDE, (short) 0x0140);
		byte[] name = ".text".getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(name, 0, data, 0x188, name.length);
		b.putInt(0x194, 0x1000);
		b.putInt(0x198, 0x200);
		b.putInt(0x19C, 0x400);
		b.putInt(0x1AC, 0x60000020);
		return data;
	}

	private static NuclrResource resource(String name, byte[] content) {
		NuclrResource resource = new NuclrResource(null) {
			private static final long serialVersionUID = 1L;

			@Override
			public InputStream openInputStream(OpenOption... options) {
				return new ByteArrayInputStream(content);
			}
		};
		resource.setUuid(name);
		resource.setName(name);
		resource.setLength(content.length);
		return resource;
	}
}
