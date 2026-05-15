package eu.vilaca.security.alert;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.vilaca.security.alert.model.Message;
import eu.vilaca.security.alert.model.MessageLine;
import lombok.extern.log4j.Log4j2;
import okhttp3.Credentials;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

import eu.vilaca.security.observability.Metrics;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

@Log4j2
public class AlertManagerClient {

	private static final int MAX_RETRIES = 3;
	private static final long RETRY_DELAY_MS = 1000;

	private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
			.connectTimeout(10, TimeUnit.SECONDS)
			.readTimeout(10, TimeUnit.SECONDS)
			.writeTimeout(10, TimeUnit.SECONDS)
			.build();

	private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter
			.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
			.withZone(ZoneOffset.UTC);

	public static void sendAlert(Configuration conf, Message msg) {
		msg.content()
				.stream()
				.filter(ml -> ml.getEndsAt() == null)
				.forEach(ml -> setDuration(conf, ml));
		final var json = createJson(msg);
		final var credential = Credentials.basic(conf.user(), conf.password());
		final var request = new Request.Builder()
				.url(conf.url())
				.post(RequestBody.create(json, MediaType.parse("application/json")))
				.header("Authorization", credential)
				.build();

		for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
			try {
				final var response = CLIENT.newCall(request).execute();
				try {
					if (response.isSuccessful()) {
						Metrics.ALERTS_SENT_TOTAL.inc();
						return;
					}
					log.error("Error on call to alertmanager. Status: {} (attempt {}/{}).",
							response.code(), attempt, MAX_RETRIES);
				} finally {
					response.close();
				}
			} catch (IOException ex) {
				log.error("Exception calling alertmanager (attempt {}/{}).", attempt, MAX_RETRIES, ex);
			}
			if (attempt < MAX_RETRIES) {
				try {
					Thread.sleep(RETRY_DELAY_MS * attempt);
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					return;
				}
			}
		}
		Metrics.ALERTS_FAILED_TOTAL.inc();
		log.error("Failed to send alert after {} attempts.", MAX_RETRIES);
	}

	private static String createJson(Message msg) {
		String json;
		try {
			json = new ObjectMapper().configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
					.writeValueAsString(msg.content());
		} catch (JsonProcessingException e) {
			json = "[{\"labels\":{\"alertname\":\"Error in application!\"},\"endsAt\":\"2099-01-01T00:00:00-00:00\"}]";
		}
		return json;
	}

	private static void setDuration(Configuration conf, MessageLine ml) {
		final var endsAt = DATE_FORMAT.format(
				Instant.now().plusMillis(conf.defaultDuration()));
		ml.setEndsAt(endsAt);
	}
}
