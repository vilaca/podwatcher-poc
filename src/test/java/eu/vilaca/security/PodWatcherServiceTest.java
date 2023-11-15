package eu.vilaca.security;

import eu.vilaca.security.alert.Configuration;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.util.Config;
import org.junit.Test;

import java.io.IOException;

public class PodWatcherServiceTest {

	@Test
	public void test() throws IOException, ApiException {
		final var conf = new Configuration().url("http://localhost:9093/api/v1/alerts")
				.user("admin")
				.password("admin");
		final var client = Config.fromConfig("/Users/joaovilaca/work/hetzner-cloud/bootstrap_kubeconfig.yaml");
//		final var rule = Rule.builder()
//				//.namespace(RuleFilter.builder().exclude(List.of("kube-system")).build())
//				.repository(AllowList.builder().allowed(List.of("koko")).build())
//				.build();
//		final var violations = new PodWatcherService(client)
//				.watch(List.of(rule));
//
//		violations.stream()
//				.map(Message::new)
//				.forEach(m -> AlertManagerClient.sendAlert(conf, m));
	}
}
