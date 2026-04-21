package eu.vilaca.security.observability;

import com.sun.net.httpserver.HttpServer;
import io.prometheus.client.CollectorRegistry;
import io.prometheus.client.exporter.common.TextFormat;
import lombok.extern.log4j.Log4j2;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

@Log4j2
public class HealthServer {

	private static final int DEFAULT_PORT = 8080;
	private final HttpServer server;

	public HealthServer() throws IOException {
		final var port = getPort();
		server = HttpServer.create(new InetSocketAddress(port), 0);

		server.createContext("/healthz", exchange -> {
			final var response = "ok";
			exchange.sendResponseHeaders(200, response.length());
			try (final var os = exchange.getResponseBody()) {
				os.write(response.getBytes(StandardCharsets.UTF_8));
			}
		});

		server.createContext("/metrics", exchange -> {
			exchange.getResponseHeaders().set("Content-Type", TextFormat.CONTENT_TYPE_004);
			exchange.sendResponseHeaders(200, 0);
			try (final var writer = new OutputStreamWriter(exchange.getResponseBody(), StandardCharsets.UTF_8)) {
				TextFormat.write004(writer, CollectorRegistry.defaultRegistry.metricFamilySamples());
			}
		});

		server.setExecutor(null);
	}

	public void start() {
		server.start();
		log.info("Health and metrics server started on port {}.", server.getAddress().getPort());
	}

	public void stop() {
		server.stop(1);
		log.info("Health and metrics server stopped.");
	}

	private static int getPort() {
		final var portEnv = System.getenv("HEALTH_PORT");
		if (portEnv != null && !portEnv.isBlank()) {
			try {
				return Integer.parseInt(portEnv);
			} catch (NumberFormatException e) {
				log.warn("Invalid HEALTH_PORT '{}', using default {}.", portEnv, DEFAULT_PORT);
			}
		}
		return DEFAULT_PORT;
	}
}
