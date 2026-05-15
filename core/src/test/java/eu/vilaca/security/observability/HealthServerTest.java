package eu.vilaca.security.observability;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.*;

public class HealthServerTest {

	private HealthServer server;
	private final OkHttpClient client = new OkHttpClient();

	@Before
	public void setUp() throws IOException {
		server = new HealthServer();
		server.start();
	}

	@After
	public void tearDown() {
		server.stop();
	}

	@Test
	public void healthEndpointReturns200() throws IOException {
		final var request = new Request.Builder()
				.url("http://localhost:8080/healthz")
				.build();
		try (final var response = client.newCall(request).execute()) {
			assertEquals(200, response.code());
			assertEquals("ok", response.body().string());
		}
	}

	@Test
	public void metricsEndpointReturns200() throws IOException {
		final var request = new Request.Builder()
				.url("http://localhost:8080/metrics")
				.build();
		try (final var response = client.newCall(request).execute()) {
			assertEquals(200, response.code());
			final var body = response.body().string();
			assertTrue(body.contains("podwatcher_"));
		}
	}

	@Test
	public void metricsContentTypeIsPrometheus() throws IOException {
		final var request = new Request.Builder()
				.url("http://localhost:8080/metrics")
				.build();
		try (final var response = client.newCall(request).execute()) {
			assertTrue(response.header("Content-Type").contains("text/plain"));
		}
	}

	@Test
	public void metricsContainsRegisteredCounters() throws IOException {
		// Increment a counter so it shows up
		Metrics.ALERTS_SENT_TOTAL.inc();

		final var request = new Request.Builder()
				.url("http://localhost:8080/metrics")
				.build();
		try (final var response = client.newCall(request).execute()) {
			final var body = response.body().string();
			assertTrue(body.contains("podwatcher_alerts_sent_total"));
			assertTrue(body.contains("podwatcher_violations_total"));
			assertTrue(body.contains("podwatcher_scan_duration_seconds"));
			assertTrue(body.contains("podwatcher_rules_loaded"));
		}
	}
}
