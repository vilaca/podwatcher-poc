package eu.vilaca.security.violation;

import org.junit.Test;

import static org.junit.Assert.*;

public class ImageDataTest {

	// --- Full image references (registry/name:tag@sha256:...) ---

	@Test
	public void fullImageReference() {
		final var img = new ImageData("docker.io/library/nginx:1.25@sha256:abc123");
		assertEquals("docker.io", img.getRegistry());
		assertEquals("nginx", img.getName());
		assertNotNull(img.getTag());
		assertNotNull(img.getSha256());
	}

	// --- Registry + name + tag ---

	@Test
	public void registryWithNameAndTag() {
		final var img = new ImageData("registry.k8s.io/kube-proxy:v1.28.0");
		assertEquals("registry.k8s.io", img.getRegistry());
		assertEquals("kube-proxy", img.getName());
		assertEquals("v1.28.0", img.getTag());
		assertNull(img.getSha256());
	}

	@Test
	public void dockerHubOfficialWithTag() {
		final var img = new ImageData("docker.io/nginx:latest");
		assertEquals("docker.io", img.getRegistry());
		assertEquals("nginx", img.getName());
		assertEquals("latest", img.getTag());
		assertNull(img.getSha256());
	}

	@Test
	public void registryWithNestedPathAndTag() {
		final var img = new ImageData("ghcr.io/org/sub/image:v2.0");
		assertEquals("ghcr.io", img.getRegistry());
		assertEquals("image", img.getName());
		assertEquals("v2.0", img.getTag());
	}

	// --- Registry + name, no tag ---

	@Test
	public void registryWithNameNoTag() {
		final var img = new ImageData("quay.io/prometheus/node-exporter");
		assertEquals("quay.io", img.getRegistry());
		assertEquals("node-exporter", img.getName());
		assertNull(img.getTag());
		assertNull(img.getSha256());
	}

	// --- SHA256 only (no tag) ---

	@Test
	public void registryWithSha256Only() {
		final var img = new ImageData("docker.io/nginx@sha256:deadbeef");
		assertEquals("docker.io", img.getRegistry());
		assertEquals("nginx", img.getName());
		assertNull(img.getTag());
		assertEquals("sha256:deadbeef", img.getSha256());
	}

	// --- Images WITHOUT a registry (known bugs - these document current broken behavior) ---

	@Test
	public void bareImageName_noRegistryNoTag() {
		// "nginx" has no '/' so image.indexOf('/') returns -1
		// This will throw StringIndexOutOfBoundsException in current code
		try {
			new ImageData("nginx");
			fail("Expected exception for image without registry");
		} catch (StringIndexOutOfBoundsException e) {
			// Current behavior: crashes
		}
	}

	@Test
	public void bareImageNameWithTag() {
		// "nginx:latest" has no '/' so image.indexOf('/') returns -1
		try {
			new ImageData("nginx:latest");
			fail("Expected exception for image without registry");
		} catch (StringIndexOutOfBoundsException e) {
			// Current behavior: crashes
		}
	}

	@Test
	public void bareImageNameWithSha256() {
		// "nginx@sha256:abc" has no '/'
		try {
			new ImageData("nginx@sha256:abc");
			fail("Expected exception for image without registry");
		} catch (StringIndexOutOfBoundsException e) {
			// Current behavior: crashes
		}
	}

	// --- Null and empty ---

	@Test
	public void nullImage() {
		final var img = new ImageData(null);
		assertNull(img.getRegistry());
		assertNull(img.getName());
		assertNull(img.getTag());
		assertNull(img.getSha256());
	}

	@Test
	public void emptyString() {
		// Empty string: indexOf('/') returns -1
		try {
			new ImageData("");
			fail("Expected exception for empty image string");
		} catch (StringIndexOutOfBoundsException e) {
			// Current behavior: crashes
		}
	}

	// --- Port in registry ---

	@Test
	public void registryWithPort() {
		final var img = new ImageData("localhost:5000/myimage:v1");
		// The ':' in "localhost:5000" may confuse tag parsing
		// since indexOf(':') finds the port colon first
		assertNotNull(img.getRegistry());
		assertNotNull(img.getName());
	}

	@Test
	public void privateRegistryWithPort() {
		final var img = new ImageData("registry.example.com:5000/org/app:2.0");
		assertEquals("registry.example.com:5000", img.getRegistry());
		assertEquals("app", img.getName());
		// Tag parsing may get confused by the port colon
	}

	// --- pretty() method ---

	@Test
	public void prettyWithTag() {
		final var img = new ImageData("docker.io/nginx:latest");
		final var pretty = img.pretty();
		assertTrue(pretty.contains("docker.io"));
		assertTrue(pretty.contains("nginx"));
		assertTrue(pretty.contains("latest"));
	}

	@Test
	public void prettyWithSha256() {
		final var img = new ImageData("docker.io/nginx@sha256:abc123");
		final var pretty = img.pretty();
		assertTrue(pretty.contains("docker.io"));
		assertTrue(pretty.contains("nginx"));
		assertTrue(pretty.contains("sha256:abc123"));
	}

	@Test
	public void prettyNoTagNoSha() {
		final var img = new ImageData("docker.io/nginx");
		final var pretty = img.pretty();
		assertEquals("docker.io/nginx", pretty);
	}

	@Test
	public void prettyNullImage() {
		final var img = new ImageData(null);
		// pretty() will produce "null/null" since registry and name are null
		final var pretty = img.pretty();
		assertEquals("null/null", pretty);
	}

	// --- Edge cases with colons and @ symbols ---

	@Test
	public void tagContainsSpecialChars() {
		final var img = new ImageData("docker.io/myapp:v1.2.3-beta+build.456");
		assertEquals("docker.io", img.getRegistry());
		assertEquals("myapp", img.getName());
		assertEquals("v1.2.3-beta+build.456", img.getTag());
	}

	@Test
	public void tagAndSha256Together() {
		final var img = new ImageData("docker.io/nginx:1.25@sha256:abc123");
		assertEquals("docker.io", img.getRegistry());
		assertEquals("nginx", img.getName());
		// When both tag and sha256 exist, current code does:
		// tag = image.substring(tag + 1) which includes everything after ':'
		// sha256 = image.substring(sha256 + 1) which is "sha256:abc123"
		assertNotNull(img.getTag());
		assertNotNull(img.getSha256());
	}

	// --- Equals and hashCode via Lombok @Data ---

	@Test
	public void equalImages() {
		final var a = new ImageData("docker.io/nginx:latest");
		final var b = new ImageData("docker.io/nginx:latest");
		assertEquals(a, b);
		assertEquals(a.hashCode(), b.hashCode());
	}

	@Test
	public void differentImages() {
		final var a = new ImageData("docker.io/nginx:latest");
		final var b = new ImageData("docker.io/nginx:1.25");
		assertNotEquals(a, b);
	}

	@Test
	public void twoNullImages() {
		final var a = new ImageData(null);
		final var b = new ImageData(null);
		assertEquals(a, b);
	}
}
