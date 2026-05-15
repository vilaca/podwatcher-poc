package eu.vilaca.security.docker;

import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.Capability;
import com.github.dockerjava.api.model.ContainerConfig;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.HostConfig;
import eu.vilaca.security.rule.Context;
import eu.vilaca.security.violation.ImageData;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class DockerContextBuilder {

	public static Context buildContext(InspectContainerResponse inspect) {
		final var ctx = new Context();
		final var config = inspect.getConfig();
		final var hostConfig = inspect.getHostConfig();

		ctx.metadata = buildMetadata(inspect);
		ctx.spec = buildSpec(hostConfig);
		ctx.securityContext = new Context.PodSecurityContext();
		ctx.container = buildContainer(inspect, config, hostConfig);

		return ctx;
	}

	public static String containerName(InspectContainerResponse inspect) {
		final var name = inspect.getName();
		if (name != null && name.startsWith("/")) {
			return name.substring(1);
		}
		return name;
	}

	private static Context.Metadata buildMetadata(InspectContainerResponse inspect) {
		final var m = new Context.Metadata();
		m.name = containerName(inspect);
		m.namespace = "docker";
		final var config = inspect.getConfig();
		if (config != null && config.getLabels() != null) {
			m.labels = config.getLabels();
		}
		return m;
	}

	private static Context.Spec buildSpec(HostConfig hostConfig) {
		final var spec = new Context.Spec();
		if (hostConfig != null) {
			spec.hostPID = "host".equals(hostConfig.getPidMode());
			spec.hostNetwork = "host".equals(hostConfig.getNetworkMode());
			spec.hostIPC = "host".equals(hostConfig.getIpcMode());
		}
		return spec;
	}

	private static Context.Container buildContainer(InspectContainerResponse inspect,
													 ContainerConfig config, HostConfig hostConfig) {
		final var container = new Context.Container();
		container.containerType = "standard";
		container.name = containerName(inspect);

		if (config != null) {
			container.image = new ImageData(config.getImage());
			container.command = buildCommand(config.getEntrypoint(), config.getCmd());
			container.ports = buildPorts(config.getExposedPorts());
		} else {
			container.image = new ImageData(null);
		}

		container.securityContext = buildSecurityContext(config, hostConfig);
		if (container.securityContext.capabilities == null) {
			container.securityContext.capabilities = new Context.Capabilities();
		}

		return container;
	}

	private static List<String> buildCommand(String[] entrypoint, String[] cmd) {
		final var command = new ArrayList<String>();
		if (entrypoint != null) {
			Collections.addAll(command, entrypoint);
		}
		if (cmd != null) {
			Collections.addAll(command, cmd);
		}
		return command.isEmpty() ? Collections.emptyList() : command;
	}

	private static List<Integer> buildPorts(ExposedPort[] exposedPorts) {
		if (exposedPorts == null || exposedPorts.length == 0) {
			return Collections.emptyList();
		}
		return Arrays.stream(exposedPorts)
				.map(ExposedPort::getPort)
				.collect(Collectors.toList());
	}

	private static Context.ContainerSecurityContext buildSecurityContext(ContainerConfig config,
																		HostConfig hostConfig) {
		final var sec = new Context.ContainerSecurityContext();

		if (hostConfig != null) {
			sec.privileged = hostConfig.getPrivileged();
			sec.readOnlyRootFilesystem = hostConfig.getReadonlyRootfs();
			sec.capabilities = buildCapabilities(hostConfig.getCapAdd(), hostConfig.getCapDrop());
			parseSecurityOpts(hostConfig.getSecurityOpts(), sec);
		}

		if (config != null && config.getUser() != null && !config.getUser().isEmpty()) {
			parseUser(config.getUser(), sec);
		}

		return sec;
	}

	private static Context.Capabilities buildCapabilities(Capability[] capAdd, Capability[] capDrop) {
		final var caps = new Context.Capabilities();
		if (capAdd != null) {
			caps.add = Arrays.stream(capAdd).map(Capability::name).collect(Collectors.toList());
		}
		if (capDrop != null) {
			caps.drop = Arrays.stream(capDrop).map(Capability::name).collect(Collectors.toList());
		}
		return caps;
	}

	private static void parseSecurityOpts(List<String> securityOpts,
										  Context.ContainerSecurityContext sec) {
		if (securityOpts == null) {
			return;
		}
		for (final var opt : securityOpts) {
			if ("no-new-privileges".equals(opt) || "no-new-privileges:true".equals(opt)) {
				sec.allowPrivilegeEscalation = false;
			}
			if (opt.startsWith("seccomp=")) {
				final var profile = opt.substring("seccomp=".length());
				if ("unconfined".equalsIgnoreCase(profile)) {
					sec.seccompProfileType = "Unconfined";
				} else {
					sec.seccompProfileType = "RuntimeDefault";
				}
			}
		}
	}

	static void parseUser(String user, Context.ContainerSecurityContext sec) {
		final var parts = user.split(":");
		sec.runAsUser = parseLongOrNull(parts[0]);
		if (parts.length > 1) {
			sec.runAsGroup = parseLongOrNull(parts[1]);
		}
	}

	private static Long parseLongOrNull(String value) {
		try {
			return Long.parseLong(value);
		} catch (NumberFormatException e) {
			return null;
		}
	}
}
