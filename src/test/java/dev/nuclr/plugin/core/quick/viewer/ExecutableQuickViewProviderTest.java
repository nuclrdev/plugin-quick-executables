package dev.nuclr.plugin.core.quick.viewer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.nuclr.platform.plugin.NuclrResource;

class ExecutableQuickViewProviderTest {

	@Test
	void supportsExtensionlessMachOByHeader(@TempDir Path tempDir) throws Exception {
		Path binary = tempDir.resolve("tool");
		Files.write(binary, new byte[] {
				(byte) 0xCF, (byte) 0xFA, (byte) 0xED, (byte) 0xFE,
				0, 0, 0, 0
		});

		NuclrResource resource = new NuclrResource(binary) {};

		assertTrue(new ExecutableQuickViewProvider().supports(resource.getPath()));
	}

	@Test
	void rejectsExtensionlessPlainTextFile(@TempDir Path tempDir) throws Exception {
		Path file = tempDir.resolve("notes");
		Files.writeString(file, "hello");

		NuclrResource resource = new NuclrResource(file) {};

		assertFalse(new ExecutableQuickViewProvider().supports(resource.getPath()));
	}
}
