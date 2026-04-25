package eu.vilaca.security;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import eu.vilaca.security.alert.AlertManagerClient;
import eu.vilaca.security.alert.Configuration;
import eu.vilaca.security.alert.model.AlertTemplate;
import eu.vilaca.security.alert.model.Message;
import eu.vilaca.security.docker.DockerWatcherService;
import eu.vilaca.security.observability.HealthServer;
import eu.vilaca.security.observability.Metrics;
import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.service.PodWatcherService;
import eu.vilaca.security.service.WatcherService;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.util.Config;
import lombok.extern.log4j.Log4j2;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Log4j2
public class PodWatcherApp {

	private static final ObjectMapper YAML_MAPPER = createYamlMapper();

	private static ObjectMapper createYamlMapper() {
		final var om = new ObjectMapper(new YAMLFactory());
		om.findAndRegisterModules();
		om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		return om;
	}

	public static void main(String[] args) {
		HealthServer healthServer = null;
		try {
			healthServer = new HealthServer();
			healthServer.start();
		} catch (Exception e) {
			log.warn("Could not start health/metrics server.", e);
		}

		try {
			run();
		} finally {
			if (healthServer != null) {
				healthServer.stop();
			}
		}
	}

	private static void run() {
		final var amConfiguration = getAmConfiguration();
		if (amConfiguration.password() == null || amConfiguration.password().isBlank()
				|| amConfiguration.user() == null || amConfiguration.user().isBlank()
				|| amConfiguration.url() == null || amConfiguration.url().isBlank()) {
			log.error("Missing required alert-manager configuration.");
			return;
		}
		final var alerts = readAlertTemplates()
				.stream()
				.collect(Collectors.toMap(AlertTemplate::getName, Function.identity()));
		if (alerts.isEmpty()) {
			log.error("No alert templates found. Exiting.");
			return;
		}
		final var rules = readRules();
		if (rules.isEmpty()) {
			log.error("No rules available. Exiting.");
			return;
		}
		final var errors = validate(rules, alerts);
		if (!errors.isEmpty()) {
			errors.forEach(err -> log.error("Config validation failed: {}", err));
			log.error("Aborting due to {} configuration error(s).", errors.size());
			System.exit(1);
			return;
		}
		Metrics.RULES_LOADED.set(rules.size());
		log.info("Loaded {} rules.", rules.size());

		final var timer = Metrics.SCAN_DURATION_SECONDS.startTimer();
		try {
			final var watcherService = createWatcherService();
			final var violations = watcherService.watch(rules);
			violations.forEach(v -> sendAlerts(amConfiguration, alerts, v));
		} finally {
			timer.observeDuration();
			Metrics.LAST_SCAN_TIMESTAMP.setToCurrentTime();
		}
		log.info("Scan complete.");
	}

	static List<String> validate(List<Rule> rules, Map<String, AlertTemplate> alerts) {
		final var errors = new ArrayList<String>();
		for (final var template : alerts.values()) {
			if (template.getName() == null || template.getName().isBlank()) {
				errors.add("Alert template has no name.");
			}
			if (template.getLabels() == null || template.getLabels().isEmpty()) {
				errors.add("Alert template '" + template.getName() + "' has no labels defined.");
			}
		}
		for (final var rule : rules) {
			if (rule.getRule() == null || rule.getRule().isBlank()) {
				errors.add("Rule '" + rule.getName() + "' has no SpEL expression defined.");
			}
			if (rule.getAlert() == null || rule.getAlert().isBlank()) {
				errors.add("Rule '" + rule.getName() + "' has no alert template reference.");
			} else if (!alerts.containsKey(rule.getAlert())) {
				errors.add("Rule '" + rule.getName() + "' references unknown alert template '" + rule.getAlert() + "'.");
			}
		}
		return errors;
	}

	private static void sendAlerts(Configuration amConfiguration,
								   Map<String, AlertTemplate> alerts, PodRuleViolation v) {
		final var template = alerts.get(v.getRule().getAlert());
		if (template == null) {
			log.error("No alert template found for '{}'. Skipping alert.", v.getRule().getAlert());
			return;
		}
		final var message = new HashMap<String, String>();
		final var labels = v.createLabels();
		if (template.getLabels() != null) {
			template.getLabels()
					.forEach(l -> message.put(l, labels.get(l)));
		}
		if (template.getEnv() != null && !template.getEnv().isBlank()) {
			message.put("env", template.getEnv());
		}
		if (template.getGroup() != null && !template.getGroup().isBlank()) {
			message.put("group", template.getGroup());
		}
		AlertManagerClient.sendAlert(amConfiguration, new Message(message));
	}

	private static WatcherService createWatcherService() {
		final var scanMode = System.getenv("SCAN_MODE");
		if ("docker".equalsIgnoreCase(scanMode)) {
			log.info("Scan mode: Docker");
			return new DockerWatcherService(createDockerClient());
		}
		log.info("Scan mode: Kubernetes");
		return new PodWatcherService(createApiClient());
	}

	private static ApiClient createApiClient() {
		final var kc = System.getenv("KUBECONFIG");
		if (kc != null && !kc.isBlank()) {
			try {
				return Config.fromConfig(kc);
			} catch (IOException e) {
				log.error("Can't create client for kc: " + kc, e);
			}
		}
		final var k8s = System.getenv("KUBERNETES_SERVICE_HOST");
		if (k8s != null && !k8s.isBlank()) {
			try {
				return Config.fromCluster();
			} catch (IOException e) {
				log.error("Can't create api client.", e);
				System.exit(1);
			}
		}
		try {
			log.info("Using default k8s api client.");
			return Config.defaultClient();
		} catch (IOException e) {
			log.error("Can't create api client.", e);
		}
		System.exit(1);
		return null;
	}

	private static DockerClient createDockerClient() {
		final var config = DefaultDockerClientConfig.createDefaultConfigBuilder().build();
		final var httpClient = new ApacheDockerHttpClient.Builder()
				.dockerHost(config.getDockerHost())
				.build();
		return DockerClientImpl.getInstance(config, httpClient);
	}

	private static List<AlertTemplate> readAlertTemplates() {
		final var templatesFolder = System.getenv("ALERT_TEMPLATES_FOLDER");
		if (templatesFolder == null || templatesFolder.isBlank()) {
			log.error("ALERT_TEMPLATES_FOLDER environment variable is not set.");
			return Collections.emptyList();
		}
		final var folder = Paths.get(templatesFolder);
		if (!Files.isDirectory(folder)) {
			log.error("ALERT_TEMPLATES_FOLDER '{}' does not exist or is not a directory.", templatesFolder);
			return Collections.emptyList();
		}
		try (Stream<Path> paths = Files.walk(folder)) {
			return paths.filter(Files::isRegularFile)
					.map(PodWatcherApp::readAlertTemplates)
					.filter(Objects::nonNull)
					.collect(Collectors.toList());
		} catch (IOException e) {
			log.error("Error reading alert templates from folder '{}'.", templatesFolder, e);
			return Collections.emptyList();
		}
	}

	private static AlertTemplate readAlertTemplates(Path file) {
		try {
			return YAML_MAPPER.readValue(new File(file.toString()), AlertTemplate.class);
		} catch (IOException e) {
			log.error("Error reading alert file {}.", file.getFileName(), e);
			return null;
		}
	}

	private static List<Rule> readRules() {
		final var rulesFolder = System.getenv("RULES_FOLDER");
		if (rulesFolder == null || rulesFolder.isBlank()) {
			log.error("RULES_FOLDER environment variable is not set.");
			return Collections.emptyList();
		}
		final var folder = Paths.get(rulesFolder);
		if (!Files.isDirectory(folder)) {
			log.error("RULES_FOLDER '{}' does not exist or is not a directory.", rulesFolder);
			return Collections.emptyList();
		}
		try (Stream<Path> paths = Files.walk(folder)) {
			return paths.filter(Files::isRegularFile)
					.map(PodWatcherApp::getPodWatcherRule)
					.filter(Objects::nonNull)
					.filter(Rule::isEnabled)
					.collect(Collectors.toList());
		} catch (IOException e) {
			log.error("Error reading rules from folder '{}'.", rulesFolder, e);
			return Collections.emptyList();
		}
	}

	private static Rule getPodWatcherRule(Path file) {
		try {
			return YAML_MAPPER.readValue(new File(file.toString()), Rule.class);
		} catch (IOException e) {
			log.error("Error reading rule file {}.", file.getFileName(), e);
			return null;
		}
	}

	private static Configuration getAmConfiguration() {
		final var am = initializeAlertConfiguration();
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

	private static Configuration initializeAlertConfiguration() {
		try (final var is = PodWatcherApp.class.getResourceAsStream("/default.yaml")) {
			if (is == null) {
				log.info("No default AlertManager config found on classpath.");
				return new Configuration();
			}
			return YAML_MAPPER.readValue(is, Configuration.class);
		} catch (Exception ex) {
			log.info("Unable to open AlertManager default config.");
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
