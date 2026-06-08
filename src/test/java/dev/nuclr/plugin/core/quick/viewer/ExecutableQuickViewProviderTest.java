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

		NuclrResource resource = resourceFor(binary);

		assertTrue(new ExecutableQuickViewProvider().supports(resource));
	}

	@Test
	void rejectsExtensionlessPlainTextFile(@TempDir Path tempDir) throws Exception {
		Path file = tempDir.resolve("notes");
		Files.writeString(file, "hello");

		NuclrResource resource = resourceFor(file);

		assertFalse(new ExecutableQuickViewProvider().supports(resource));
	}

	private static NuclrResource resourceFor(Path path) {
		NuclrResource resource = new NuclrResource(path) {
			@Override
			public java.io.InputStream openInputStream(java.nio.file.OpenOption... options) throws Exception {
				return Files.newInputStream(getPath(), options);
			}
		};
		resource.setName(path.getFileName().toString());
		return resource;
	}
}
