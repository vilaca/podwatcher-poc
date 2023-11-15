package eu.vilaca.security;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import eu.vilaca.security.alert.Configuration;
import eu.vilaca.security.alert.AlertManagerClient;
import eu.vilaca.security.alert.model.AlertTemplate;
import eu.vilaca.security.alert.model.Message;
import eu.vilaca.security.rule.Rule;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.util.Config;
import lombok.extern.log4j.Log4j2;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Log4j2
public class PodWatcherApp {
	public static void main(String[] args) {

		final var amConfiguration = getAmConfiguration();
		final var rules = readRules();
		final var alerts = readAlertTemplates().stream()
				.collect(Collectors.toMap(AlertTemplate::getName, Function.identity()));
		if (rules.isEmpty()) {
			log.error("No rules available. Exiting.");
			return;
		}
		if (alerts.isEmpty()) {
			log.error("No alert templates found. Exiting.");
			return;
		}
		final var violations = new PodWatcherService(createApiClient()).watch(rules);
		violations.forEach(
				v -> {
					final var template = alerts.get(v.getRule().getAlert());
					final var message = new HashMap<String, String>();
					final var labels = v.createLabels();
					template.getLabels()
							.forEach(l -> message.put(l, labels.get(l)));
					if (template.getEnv() != null && !template.getEnv().isBlank()) {
						message.put("env", template.getEnv());
					}
					if (template.getGroup() != null && !template.getGroup().isBlank()) {
						message.put("group", template.getGroup());
					}
					AlertManagerClient.sendAlert(amConfiguration, new Message(message));
				}
		);
	}

	private static ApiClient createApiClient() {
		final var kc = System.getenv("KUBECONFIG");
		if (kc != null) {
			try {
				return Config.fromConfig(kc);
			} catch (IOException e) {
				log.error("Can't create client for kc: " + kc, e);
			}
		}
		final var k8s = System.getenv("KUBERNETES_SERVICE_HOST");
		if (k8s != null) {
			try {
				return Config.fromCluster();
			} catch (IOException e) {
				log.error("Can't create api client.", e);
				System.exit(1);
			}
		}
		try {
			return Config.defaultClient();
		} catch (IOException e) {
			log.error("Can't create api client.", e);
		}
		System.exit(1);
		return null;
	}

	private static List<AlertTemplate> readAlertTemplates() {
		final var templatesFolder = System.getenv("ALERT_TEMPLATES_FOLDER");
		if (templatesFolder == null) {
			return Collections.emptyList();
		}
		try (Stream<Path> paths = Files.walk(Paths.get(templatesFolder))) {
			return paths.filter(Files::isRegularFile)
					.map(PodWatcherApp::readAlertTemplates)
					.filter(Objects::nonNull)
					.collect(Collectors.toList());
		} catch (IOException e) {
			log.error(e);
			return Collections.emptyList();
		}
	}

	private static AlertTemplate readAlertTemplates(Path file) {
		try {
			final var om = new ObjectMapper(new YAMLFactory());
			om.findAndRegisterModules();
			om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			return om.readValue(new File(file.toString()), AlertTemplate.class);
		} catch (IOException e) {
			log.error(e);
			return null;
		}
	}

	private static List<Rule> readRules() {
		final var rulesFolder = System.getenv("RULES_FOLDER");
		if (rulesFolder == null) {
			return Collections.emptyList();
		}
		try (Stream<Path> paths = Files.walk(Paths.get(rulesFolder))) {
			return paths.filter(Files::isRegularFile)
					.map(PodWatcherApp::getPodWatcherRule)
					.filter(Objects::nonNull)
					.collect(Collectors.toList());
		} catch (IOException e) {
			log.error(e);
			return Collections.emptyList();
		}
	}

	private static Rule getPodWatcherRule(Path file) {
		try {
			final var om = new ObjectMapper(new YAMLFactory());
			om.findAndRegisterModules();
			om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			//om.reader().without(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
			return om.readValue(new File(file.toString()), Rule.class);
		} catch (IOException e) {
			log.error(e);
			return null;
		}
	}

	private static Configuration getAmConfiguration() {
		final var am = initializeAlertConfi();
		final int defaultDuration = useDefaultIfNull(System.getenv("AM_DEFAULT_DURATION"), -1);
		if (defaultDuration != -1) {
			am.defaultDuration(defaultDuration);
		}
		final var url = System.getenv("AM_URL");
		if (url != null) {
			am.url(url);
		}
		final var user = System.getenv("AM_USER");
		if (user != null) {
			am.user(user);
		}
		final var password = System.getenv("AM_PASSWORD");
		if (password != null) {
			am.password(password);
		}
		return am;
	}

	private static Configuration initializeAlertConfi() {
		try {
			final var om = new ObjectMapper(new YAMLFactory());
			om.findAndRegisterModules();
			return om.readValue(new File("src/main/resources/default.yaml"), Configuration.class);
		} catch (Exception ex) {
			log.warn("Unable to open AlertManager default config.", ex);
			return new Configuration();
		}
	}

	private static int useDefaultIfNull(String value, int i) {
		try {
			return Integer.parseInt(value);
		} catch (Exception ex) {
			return i;
		}
	}
}
