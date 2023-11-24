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

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

@Log4j2
public class AlertManagerClient {
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
		final var client = new OkHttpClient().newBuilder().build();
		try {
			final var response = client.newCall(request).execute();
			if (!response.isSuccessful()) {
				log.error("Error on call to alertmanager. Status: {}.", response.code());
			}
		} catch (IOException ex) {
			log.error("Exception calling alertmanager.", ex);
		}
	}

	private static String createJson(Message msg) {
		String json;
		try {
			json = new ObjectMapper().configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
					//	.writerWithDefaultPrettyPrinter()
					.writeValueAsString(msg.content());
		} catch (JsonProcessingException e) {
			json = "[{\"labels\":{\"alertname\":\"Error in application!\"},\"endsAt\":\"2099-01-01T00:00:00-00:00\"}]";
		}
		return json;
	}

	private static void setDuration(Configuration conf, MessageLine ml) {
		final var df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		final var endsAt = df.format(new Date().getTime() + conf.defaultDuration());
		ml.setEndsAt(endsAt);
	}
}
