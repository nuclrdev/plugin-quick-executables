package dev.nuclr.plugin.core.quick.viewer.exec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

class ExecutableParserTest {

	@Test
	void parsesPeMetadata() throws Exception {
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
		putAscii(data, 0x188, ".text");
		b.putInt(0x194, 0x1000);
		b.putInt(0x198, 0x200);
		b.putInt(0x19C, 0x400);
		b.putInt(0x1AC, 0x60000020);

		ExecutableFileInfo info = ExecutableParser.parse("sample.exe", data);

		assertEquals("PE", info.getFormat());
		assertEquals("x86-64", info.getArchitecture());
		assertEquals("64-bit", info.getBitness());
		assertEquals("Windows GUI", info.getDetails().get("Subsystem"));
		assertEquals("Enabled", info.getDetails().get("ASLR"));
		assertEquals(1, info.getEntries().size());
		assertEquals(".text", info.getEntries().get(0).getName());
	}

	@Test
	void parsesElfMetadata() throws Exception {
		byte[] data = new byte[512];
		ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
		data[0] = 0x7F;
		data[1] = 'E';
		data[2] = 'L';
		data[3] = 'F';
		data[4] = 2;
		data[5] = 1;
		data[6] = 1;
		data[7] = 3;
		b.putShort(16, (short) 3);
		b.putShort(18, (short) 0x3E);
		b.putLong(24, 0x401000L);
		b.putLong(32, 64L);
		b.putLong(40, 160L);
		b.putShort(54, (short) 56);
		b.putShort(56, (short) 2);
		b.putShort(58, (short) 64);
		b.putShort(60, (short) 3);
		b.putShort(62, (short) 2);

		b.putInt(64, 3);
		b.putLong(72, 0x140L);
		b.putLong(96, 16);
		putAscii(data, 0x140, "/lib64/ld-linux");

		b.putInt(120, 2);

		b.putInt(224, 7);
		b.putLong(232, 0L);
		b.putLong(240, 0L);
		b.putLong(248, 0x180L);
		b.putLong(256, 0x30L);

		b.putInt(288, 15);
		b.putLong(296, 0L);
		b.putLong(304, 0L);
		b.putLong(312, 0x1B0L);
		b.putLong(320, 25L);

		putAscii(data, 0x1B0, "\0.text\0.symtab\0.shstrtab\0");

		ExecutableFileInfo info = ExecutableParser.parse("sample.so", data);

		assertEquals("ELF", info.getFormat());
		assertEquals("Shared object", info.getFileType());
		assertEquals("x86-64", info.getArchitecture());
		assertEquals("Yes", info.getDetails().get("Dynamic Linking"));
		assertEquals("No", info.getDetails().get("Stripped"));
		assertFalse(info.getEntries().isEmpty());
	}

	@Test
	void parsesFatMachO() throws Exception {
		byte[] data = new byte[64];
		ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
		b.putInt(0, 0xCAFEBABE);
		b.putInt(4, 2);
		b.putInt(8, 0x01000007);
		b.putInt(16, 0x1000);
		b.putInt(20, 0x2000);
		b.putInt(24, 12);
		b.putInt(28, 0x0100000C);
		b.putInt(36, 0x3000);
		b.putInt(40, 0x1800);
		b.putInt(44, 14);

		ExecutableFileInfo info = ExecutableParser.parse("universal", data);

		assertEquals("Mach-O (Universal)", info.getFormat());
		assertEquals(2, info.getEntries().size());
		assertTrue(info.getNotes().get(0).contains("Contained slices"));
	}

	@Test
	void rejectsUnknownFile() {
		ExecutableParseException ex = assertThrows(
				ExecutableParseException.class,
				() -> ExecutableParser.parse("file.bin", "hello".getBytes(StandardCharsets.UTF_8)));
		assertTrue(ex.getMessage().contains("Unrecognized executable format"));
	}

	private static void putAscii(byte[] data, int offset, String value) {
		byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
		System.arraycopy(bytes, 0, data, offset, bytes.length);
	}
}
