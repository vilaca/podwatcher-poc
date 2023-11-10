package eu.vilaca.alert;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import okhttp3.Credentials;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class AlertManagerClient {
	public static void sendAlert(AlertConfiguration conf, Message msg) {
		for (Line l : msg.content()) {
			if (l.getEndsAt() != null) continue;
			setDuration(conf, l);
		}
		String json;
		try {
			json = new ObjectMapper().configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
					.writerWithDefaultPrettyPrinter()
					.writeValueAsString(msg.content());
		} catch (JsonProcessingException e) {
			json = "[{\"labels\":{\"alertname\":\"Error in application!\"},\"endsAt\":\"2099-01-01T00:00:00-00:00\"}]";
		}
		final var credential = Credentials.basic(conf.user(), conf.password());
		final var request = new Request.Builder()
				.url(conf.url())
				.post(RequestBody.create(json, MediaType.parse("application/json")))
				.header("Authorization", credential)
				.build();
		final var client = new OkHttpClient().newBuilder().build();
		try {
			final var response = client.newCall(request).execute();
			response.newBuilder();
		} catch (IOException e) {

		}
	}

	private static void setDuration(AlertConfiguration conf, Line l) {
		final var df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		l.setEndsAt(df.format(new Date().getTime() + conf.defaultDuration()));
	}
}
