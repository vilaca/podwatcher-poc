package eu.vilaca.security;

import eu.vilaca.security.service.PodWatcherService;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.util.Config;
import lombok.extern.log4j.Log4j2;

import java.io.IOException;

@Log4j2
public class K8sScannerApp {

	public static void main(String[] args) {
		final var apiClient = createApiClient();
		final var watcherService = new PodWatcherService(apiClient);
		ScannerSupport.runScan(watcherService);
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
}
