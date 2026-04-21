package eu.vilaca.security.alert;

import eu.vilaca.security.alert.model.Message;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

public class AlertManagerClientHttpTest {

	private MockWebServer server;

	@Before
	public void setUp() throws IOException {
		server = new MockWebServer();
		server.start();
	}

	@After
	public void tearDown() throws IOException {
		server.shutdown();
	}

	private Configuration createConfig() {
		return new Configuration()
				.url(server.url("/api/v1/alerts").toString())
				.user("admin")
				.password("secret")
				.defaultDuration(300000);
	}

	// --- Successful alert ---

	@Test
	public void sendAlert_success() throws InterruptedException {
		server.enqueue(new MockResponse().setResponseCode(200));

		final var labels = new HashMap<String, String>();
		labels.put("alertname", "TestAlert");
		labels.put("severity", "critical");
		final var message = new Message(labels);

		AlertManagerClient.sendAlert(createConfig(), message);

		final var request = server.takeRequest(5, TimeUnit.SECONDS);
		assertNotNull(request);
		assertEquals("POST", request.getMethod());
		assertEquals("/api/v1/alerts", request.getPath());
	}

	@Test
	public void sendAlert_sendsJsonContentType() throws InterruptedException {
		server.enqueue(new MockResponse().setResponseCode(200));

		final var message = new Message(new HashMap<>());
		AlertManagerClient.sendAlert(createConfig(), message);

		final var request = server.takeRequest(5, TimeUnit.SECONDS);
		assertNotNull(request);
		assertTrue(request.getHeader("Content-Type").contains("application/json"));
	}

	@Test
	public void sendAlert_sendsBasicAuth() throws InterruptedException {
		server.enqueue(new MockResponse().setResponseCode(200));

		final var message = new Message(new HashMap<>());
		AlertManagerClient.sendAlert(createConfig(), message);

		final var request = server.takeRequest(5, TimeUnit.SECONDS);
		assertNotNull(request);
		final var authHeader = request.getHeader("Authorization");
		assertNotNull(authHeader);
		assertTrue(authHeader.startsWith("Basic "));
	}

	@Test
	public void sendAlert_bodyIsJsonArray() throws InterruptedException {
		server.enqueue(new MockResponse().setResponseCode(200));

		final var labels = new HashMap<String, String>();
		labels.put("rule", "test-rule");
		labels.put("namespace", "default");
		final var message = new Message(labels);

		AlertManagerClient.sendAlert(createConfig(), message);

		final var request = server.takeRequest(5, TimeUnit.SECONDS);
		assertNotNull(request);
		final var body = request.getBody().readUtf8();
		assertTrue(body.startsWith("["));
		assertTrue(body.endsWith("]"));
		assertTrue(body.contains("test-rule"));
		assertTrue(body.contains("default"));
	}

	@Test
	public void sendAlert_setsEndsAt() throws InterruptedException {
		server.enqueue(new MockResponse().setResponseCode(200));

		final var message = new Message(new HashMap<>());
		// endsAt is null initially, sendAlert should set it via setDuration
		assertNull(message.content().get(0).getEndsAt());

		AlertManagerClient.sendAlert(createConfig(), message);

		// After sending, endsAt should have been set
		assertNotNull(message.content().get(0).getEndsAt());
		assertTrue(message.content().get(0).getEndsAt().endsWith("Z"));
	}

	@Test
	public void sendAlert_preservesExistingEndsAt() throws InterruptedException {
		server.enqueue(new MockResponse().setResponseCode(200));

		final var message = new Message(new HashMap<>());
		message.content().get(0).setEndsAt("2099-01-01T00:00:00Z");

		AlertManagerClient.sendAlert(createConfig(), message);

		// Should not override existing endsAt
		assertEquals("2099-01-01T00:00:00Z", message.content().get(0).getEndsAt());
	}

	// --- Error responses ---

	@Test
	public void sendAlert_serverError_doesNotThrow() {
		server.enqueue(new MockResponse().setResponseCode(500));

		final var message = new Message(new HashMap<>());
		// Should not throw, just log the error
		AlertManagerClient.sendAlert(createConfig(), message);
	}

	@Test
	public void sendAlert_unauthorized_doesNotThrow() {
		server.enqueue(new MockResponse().setResponseCode(401));

		final var message = new Message(new HashMap<>());
		AlertManagerClient.sendAlert(createConfig(), message);
	}

	@Test
	public void sendAlert_notFound_doesNotThrow() {
		server.enqueue(new MockResponse().setResponseCode(404));

		final var message = new Message(new HashMap<>());
		AlertManagerClient.sendAlert(createConfig(), message);
	}

	// --- Connection errors ---

	@Test
	public void sendAlert_unreachableHost_doesNotThrow() throws IOException {
		server.shutdown(); // shut down so connection fails

		final var message = new Message(new HashMap<>());
		// Should not throw, just log the IOException
		AlertManagerClient.sendAlert(createConfig(), message);
	}

	// --- Labels with special characters ---

	@Test
	public void sendAlert_labelsWithSpecialChars() throws InterruptedException {
		server.enqueue(new MockResponse().setResponseCode(200));

		final var labels = new HashMap<String, String>();
		labels.put("image", "registry.io/org/app:v1.2.3-beta+build@sha256:abc");
		labels.put("rule", "my:rule/name");
		final var message = new Message(labels);

		AlertManagerClient.sendAlert(createConfig(), message);

		final var request = server.takeRequest(5, TimeUnit.SECONDS);
		final var body = request.getBody().readUtf8();
		assertTrue(body.contains("registry.io/org/app"));
	}

	// --- Multiple labels ---

	@Test
	public void sendAlert_fullLabelsSet() throws InterruptedException {
		server.enqueue(new MockResponse().setResponseCode(200));

		final var labels = new HashMap<String, String>();
		labels.put("alertname", "privileged-container");
		labels.put("rule", "priv-check");
		labels.put("namespace", "production");
		labels.put("pod", "web-server-abc123");
		labels.put("image", "docker.io/nginx:1.25");
		labels.put("env", "prod");
		labels.put("group", "security");
		final var message = new Message(labels);

		AlertManagerClient.sendAlert(createConfig(), message);

		final var request = server.takeRequest(5, TimeUnit.SECONDS);
		final var body = request.getBody().readUtf8();
		assertTrue(body.contains("privileged-container"));
		assertTrue(body.contains("production"));
		assertTrue(body.contains("web-server-abc123"));
	}
}
