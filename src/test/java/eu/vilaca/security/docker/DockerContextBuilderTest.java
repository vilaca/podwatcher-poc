package eu.vilaca.security.docker;

import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.Capability;
import com.github.dockerjava.api.model.ContainerConfig;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.ExposedPorts;
import com.github.dockerjava.api.model.HostConfig;
import eu.vilaca.security.rule.Context;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DockerContextBuilderTest {

	private InspectContainerResponse mockInspect(String name, ContainerConfig config, HostConfig hostConfig) {
		final var inspect = mock(InspectContainerResponse.class);
		when(inspect.getName()).thenReturn(name);
		when(inspect.getConfig()).thenReturn(config);
		when(inspect.getHostConfig()).thenReturn(hostConfig);
		return inspect;
	}

	// --- Container name ---

	@Test
	public void containerName_stripsLeadingSlash() {
		assertEquals("my-container",
				DockerContextBuilder.containerName(mockInspect("/my-container", null, null)));
	}

	@Test
	public void containerName_noSlash() {
		assertEquals("container",
				DockerContextBuilder.containerName(mockInspect("container", null, null)));
	}

	@Test
	public void containerName_null() {
		assertNull(DockerContextBuilder.containerName(mockInspect(null, null, null)));
	}

	// --- Metadata ---

	@Test
	public void metadata_namespaceIsDocker() {
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, null));
		assertEquals("docker", ctx.metadata.namespace);
	}

	@Test
	public void metadata_nameStripped() {
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/my-app", null, null));
		assertEquals("my-app", ctx.metadata.name);
	}

	@Test
	public void metadata_labelsFromConfig() {
		final var config = new ContainerConfig()
				.withLabels(Map.of("app", "web", "env", "prod"));
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", config, null));

		assertEquals("web", ctx.metadata.labels.get("app"));
		assertEquals("prod", ctx.metadata.labels.get("env"));
	}

	@Test
	public void metadata_labelsDefaultToEmpty() {
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, null));
		assertNotNull(ctx.metadata.labels);
		assertTrue(ctx.metadata.labels.isEmpty());
	}

	// --- Image ---

	@Test
	public void image_fromConfig() {
		final var config = new ContainerConfig().withImage("docker.io/nginx:latest");
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", config, null));

		assertEquals("docker.io", ctx.container.image.getRegistry());
		assertEquals("nginx", ctx.container.image.getName());
		assertEquals("latest", ctx.container.image.getTag());
	}

	@Test
	public void image_nullConfig() {
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, null));
		assertNotNull(ctx.container.image);
	}

	// --- Privileged ---

	@Test
	public void privileged_true() {
		final var host = new HostConfig().withPrivileged(true);
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(true, ctx.container.securityContext.privileged);
	}

	@Test
	public void privileged_false() {
		final var host = new HostConfig().withPrivileged(false);
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(false, ctx.container.securityContext.privileged);
	}

	// --- ReadOnly Root FS ---

	@Test
	public void readonlyRootfs_true() {
		final var host = new HostConfig().withReadonlyRootfs(true);
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(true, ctx.container.securityContext.readOnlyRootFilesystem);
	}

	// --- Capabilities ---

	@Test
	public void capabilities_add() {
		final var host = new HostConfig().withCapAdd(Capability.NET_ADMIN, Capability.SYS_TIME);
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(List.of("NET_ADMIN", "SYS_TIME"), ctx.container.securityContext.capabilities.add);
	}

	@Test
	public void capabilities_drop() {
		final var host = new HostConfig().withCapDrop(Capability.ALL);
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(List.of("ALL"), ctx.container.securityContext.capabilities.drop);
	}

	@Test
	public void capabilities_defaultEmpty() {
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, null));

		assertNotNull(ctx.container.securityContext.capabilities);
		assertTrue(ctx.container.securityContext.capabilities.add.isEmpty());
		assertTrue(ctx.container.securityContext.capabilities.drop.isEmpty());
	}

	// --- Host modes ---

	@Test
	public void hostPID_hostMode() {
		final var host = new HostConfig().withPidMode("host");
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(true, ctx.spec.hostPID);
	}

	@Test
	public void hostPID_notHost() {
		final var host = new HostConfig().withPidMode("");
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(false, ctx.spec.hostPID);
	}

	@Test
	public void hostNetwork_hostMode() {
		final var host = new HostConfig().withNetworkMode("host");
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(true, ctx.spec.hostNetwork);
	}

	@Test
	public void hostNetwork_bridge() {
		final var host = new HostConfig().withNetworkMode("bridge");
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(false, ctx.spec.hostNetwork);
	}

	@Test
	public void hostIPC_hostMode() {
		final var host = new HostConfig().withIpcMode("host");
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(true, ctx.spec.hostIPC);
	}

	// --- User parsing ---

	@Test
	public void user_numericUid() {
		final var sec = new Context.ContainerSecurityContext();
		DockerContextBuilder.parseUser("0", sec);
		assertEquals(Long.valueOf(0), sec.runAsUser);
		assertNull(sec.runAsGroup);
	}

	@Test
	public void user_uidAndGid() {
		final var sec = new Context.ContainerSecurityContext();
		DockerContextBuilder.parseUser("1000:1000", sec);
		assertEquals(Long.valueOf(1000), sec.runAsUser);
		assertEquals(Long.valueOf(1000), sec.runAsGroup);
	}

	@Test
	public void user_namedUser() {
		final var sec = new Context.ContainerSecurityContext();
		DockerContextBuilder.parseUser("root", sec);
		assertNull(sec.runAsUser);
	}

	@Test
	public void user_namedUserAndGroup() {
		final var sec = new Context.ContainerSecurityContext();
		DockerContextBuilder.parseUser("nobody:nogroup", sec);
		assertNull(sec.runAsUser);
		assertNull(sec.runAsGroup);
	}

	@Test
	public void user_fromFullContext() {
		final var config = new ContainerConfig().withUser("0:0");
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", config, null));

		assertEquals(Long.valueOf(0), ctx.container.securityContext.runAsUser);
		assertEquals(Long.valueOf(0), ctx.container.securityContext.runAsGroup);
	}

	// --- Command ---

	@Test
	public void command_entrypointAndCmd() {
		final var config = new ContainerConfig()
				.withEntrypoint(new String[]{"/bin/sh", "-c"})
				.withCmd(new String[]{"echo hello"});
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", config, null));

		assertEquals(List.of("/bin/sh", "-c", "echo hello"), ctx.container.command);
	}

	@Test
	public void command_onlyCmd() {
		final var config = new ContainerConfig()
				.withCmd(new String[]{"nginx", "-g", "daemon off;"});
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", config, null));

		assertEquals(List.of("nginx", "-g", "daemon off;"), ctx.container.command);
	}

	@Test
	public void command_nullBoth() {
		final var config = new ContainerConfig();
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", config, null));

		assertNotNull(ctx.container.command);
		assertTrue(ctx.container.command.isEmpty());
	}

	// --- Ports ---

	@Test
	public void ports_fromExposedPorts() {
		final var config = new ContainerConfig()
				.withExposedPorts(new ExposedPorts(ExposedPort.tcp(80), ExposedPort.tcp(443)));
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", config, null));

		assertEquals(List.of(80, 443), ctx.container.ports);
	}

	@Test
	public void ports_defaultEmpty() {
		final var config = new ContainerConfig();
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", config, null));

		assertNotNull(ctx.container.ports);
		assertTrue(ctx.container.ports.isEmpty());
	}

	// --- Security opts ---

	@Test
	public void securityOpts_noNewPrivileges() {
		final var host = new HostConfig().withSecurityOpts(List.of("no-new-privileges"));
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(false, ctx.container.securityContext.allowPrivilegeEscalation);
	}

	@Test
	public void securityOpts_seccompUnconfined() {
		final var host = new HostConfig().withSecurityOpts(List.of("seccomp=unconfined"));
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals("Unconfined", ctx.container.securityContext.seccompProfileType);
	}

	@Test
	public void securityOpts_seccompDefault() {
		final var host = new HostConfig().withSecurityOpts(List.of("seccomp=default"));
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals("RuntimeDefault", ctx.container.securityContext.seccompProfileType);
	}

	@Test
	public void securityOpts_combined() {
		final var host = new HostConfig()
				.withSecurityOpts(List.of("no-new-privileges", "seccomp=unconfined"));
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, host));

		assertEquals(false, ctx.container.securityContext.allowPrivilegeEscalation);
		assertEquals("Unconfined", ctx.container.securityContext.seccompProfileType);
	}

	// --- Container type ---

	@Test
	public void containerType_alwaysStandard() {
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, null));
		assertEquals("standard", ctx.container.containerType);
	}

	// --- Null safety ---

	@Test
	public void nullConfig_nullHostConfig() {
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, null));

		assertNotNull(ctx.container);
		assertNotNull(ctx.container.securityContext);
		assertNotNull(ctx.container.securityContext.capabilities);
		assertNotNull(ctx.spec);
		assertNotNull(ctx.securityContext);
		assertNotNull(ctx.metadata);
		assertTrue(ctx.container.command.isEmpty());
		assertTrue(ctx.container.args.isEmpty());
		assertTrue(ctx.container.ports.isEmpty());
		assertTrue(ctx.container.securityContext.capabilities.add.isEmpty());
		assertTrue(ctx.container.securityContext.capabilities.drop.isEmpty());
		assertTrue(ctx.metadata.labels.isEmpty());
		assertTrue(ctx.metadata.annotations.isEmpty());
	}

	// --- Pod-level security context defaults ---

	@Test
	public void podSecurityContext_allDefaults() {
		final var ctx = DockerContextBuilder.buildContext(mockInspect("/test", null, null));

		assertNull(ctx.securityContext.runAsUser);
		assertNull(ctx.securityContext.runAsGroup);
		assertNull(ctx.securityContext.runAsNonRoot);
		assertNull(ctx.securityContext.fsGroup);
		assertTrue(ctx.securityContext.supplementalGroups.isEmpty());
	}
}
