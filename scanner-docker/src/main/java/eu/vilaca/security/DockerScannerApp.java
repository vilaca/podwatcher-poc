package eu.vilaca.security;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import eu.vilaca.security.docker.DockerWatcherService;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class DockerScannerApp {

	public static void main(String[] args) {
		final var dockerClient = createDockerClient();
		final var watcherService = new DockerWatcherService(dockerClient);
		ScannerSupport.runScan(watcherService);
	}

	private static DockerClient createDockerClient() {
		final var config = DefaultDockerClientConfig.createDefaultConfigBuilder().build();
		final var httpClient = new ApacheDockerHttpClient.Builder()
				.dockerHost(config.getDockerHost())
				.build();
		return DockerClientImpl.getInstance(config, httpClient);
	}
}
