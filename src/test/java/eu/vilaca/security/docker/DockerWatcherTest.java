package eu.vilaca.security.docker;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.InspectContainerCmd;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.command.ListContainersCmd;
import com.github.dockerjava.api.exception.NotFoundException;
import com.github.dockerjava.api.model.Container;
import com.github.dockerjava.api.model.ContainerConfig;
import com.github.dockerjava.api.model.HostConfig;
import eu.vilaca.security.rule.Rule;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class DockerWatcherTest {

	private DockerClient client;
	private ListContainersCmd listCmd;

	@Before
	public void setUp() {
		client = mock(DockerClient.class);
		listCmd = mock(ListContainersCmd.class);
		when(client.listContainersCmd()).thenReturn(listCmd);
		when(listCmd.withStatusFilter(any())).thenReturn(listCmd);
	}

	private static Rule createRule(String name, String ruleExpr) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setEnabled(true);
		rule.setRule(ruleExpr);
		rule.setAlert("test-alert");
		return rule;
	}

	private void mockContainerList(String... ids) {
		final var containers = new java.util.ArrayList<Container>();
		for (final var id : ids) {
			final var c = mock(Container.class);
			when(c.getId()).thenReturn(id);
			containers.add(c);
		}
		when(listCmd.exec()).thenReturn(containers);
	}

	private void mockInspect(String id, String name, boolean privileged) {
		final var inspectCmd = mock(InspectContainerCmd.class);
		final var inspect = mock(InspectContainerResponse.class);
		when(inspect.getName()).thenReturn(name);
		when(inspect.getConfig()).thenReturn(new ContainerConfig().withImage("docker.io/nginx:latest"));
		when(inspect.getHostConfig()).thenReturn(new HostConfig().withPrivileged(privileged));
		when(client.inspectContainerCmd(id)).thenReturn(inspectCmd);
		when(inspectCmd.exec()).thenReturn(inspect);
	}

	private void mockInspectNotFound(String id) {
		final var inspectCmd = mock(InspectContainerCmd.class);
		when(client.inspectContainerCmd(id)).thenReturn(inspectCmd);
		when(inspectCmd.exec()).thenThrow(new NotFoundException("gone"));
	}

	@Test
	public void evaluate_findsPrivilegedContainer() {
		mockContainerList("abc123");
		mockInspect("abc123", "/my-container", true);

		final var watcher = new DockerWatcher(client);
		final var rule = createRule("priv", "container.securityContext.privileged == true");

		final var violations = watcher.evaluate(rule);
		assertEquals(1, violations.size());
		assertEquals("docker", violations.get(0).getNamespace());
		assertEquals("my-container", violations.get(0).getPod());
	}

	@Test
	public void evaluate_noViolationForSafeContainer() {
		mockContainerList("abc123");
		mockInspect("abc123", "/safe-container", false);

		final var watcher = new DockerWatcher(client);
		final var rule = createRule("priv", "container.securityContext.privileged == true");

		assertTrue(watcher.evaluate(rule).isEmpty());
	}

	@Test
	public void evaluate_multipleContainers_partialMatch() {
		mockContainerList("id1", "id2");
		mockInspect("id1", "/priv-container", true);
		mockInspect("id2", "/safe-container", false);

		final var watcher = new DockerWatcher(client);
		final var rule = createRule("priv", "container.securityContext.privileged == true");

		assertEquals(1, watcher.evaluate(rule).size());
	}

	@Test
	public void evaluate_emptyContainerList() {
		when(listCmd.exec()).thenReturn(List.of());

		final var watcher = new DockerWatcher(client);
		final var rule = createRule("priv", "container.securityContext.privileged == true");

		assertTrue(watcher.evaluate(rule).isEmpty());
	}

	@Test
	public void evaluate_containerRemovedBeforeInspect_skipped() {
		mockContainerList("gone", "present");
		mockInspectNotFound("gone");
		mockInspect("present", "/present", true);

		final var watcher = new DockerWatcher(client);
		final var rule = createRule("priv", "container.securityContext.privileged == true");

		assertEquals(1, watcher.evaluate(rule).size());
	}
}
