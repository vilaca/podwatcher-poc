package eu.vilaca.security.rule;

import eu.vilaca.security.observability.Metrics;
import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.violation.ImageData;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.models.V1Capabilities;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1ContainerPort;
import io.kubernetes.client.openapi.models.V1EphemeralContainer;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodSecurityContext;
import io.kubernetes.client.openapi.models.V1PodSpec;
import io.kubernetes.client.openapi.models.V1SecurityContext;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Log4j2
@Data
public class Rule {

	private String name;
	private boolean enabled;
	private Filter filter;
	private String rule;
	private String alert;
	private String severity;

	private transient Expression parsedExpression;

	public boolean allNamespaces() {
		return this.filter == null
				|| this.filter.getNamespace() == null
				|| this.filter.getNamespace().getExclude() != null
				|| this.filter.getNamespace().getInclude() == null;
	}

	public List<PodRuleViolation> evaluate(V1Pod pod) {
		Metrics.RULES_EVALUATED_TOTAL.labels(this.name).inc();
		final var spec = pod.getSpec();
		if (spec != null) {
			try {
				final var allContainers = collectContainers(spec);
				final var violations = allContainers.stream()
						.filter(cwt -> evaluateRule(buildContext(pod, spec, cwt.container, cwt.type)))
						.map(cwt -> new PodRuleViolation(this, pod, cwt.container))
						.collect(Collectors.toList());
				violations.forEach(v -> Metrics.VIOLATIONS_TOTAL.labels(this.name).inc());
				return violations;
			} catch (SpelEvaluationException se) {
				Metrics.RULES_ERRORS_TOTAL.labels(this.name).inc();
				log.error("Can't evaluate rule {}. {}", this.name, se.getMessage());
			} catch (Exception ex) {
				Metrics.RULES_ERRORS_TOTAL.labels(this.name).inc();
				log.error("Can't evaluate rule {}.", this.name, ex);
			}
		} else {
			log.warn("Unexpected/Corrupt cluster data. Can't evaluate rule {}", this.name);
		}
		return Collections.emptyList();
	}

	public List<PodRuleViolation> evaluate(Context ctx, String namespace, String containerName, String image) {
		Metrics.RULES_EVALUATED_TOTAL.labels(this.name).inc();
		try {
			if (evaluateRule(ctx)) {
				Metrics.VIOLATIONS_TOTAL.labels(this.name).inc();
				return List.of(new PodRuleViolation(this, namespace, containerName, image));
			}
		} catch (SpelEvaluationException se) {
			Metrics.RULES_ERRORS_TOTAL.labels(this.name).inc();
			log.error("Can't evaluate rule {}. {}", this.name, se.getMessage());
		} catch (Exception ex) {
			Metrics.RULES_ERRORS_TOTAL.labels(this.name).inc();
			log.error("Can't evaluate rule {}.", this.name, ex);
		}
		return Collections.emptyList();
	}

	private static final SpelExpressionParser PARSER = new SpelExpressionParser();

	private Expression getParsedExpression() {
		if (parsedExpression == null) {
			parsedExpression = PARSER.parseExpression(rule);
		}
		return parsedExpression;
	}

	private Boolean evaluateRule(Context ctx) {
		final var context = SimpleEvaluationContext
				.forReadOnlyDataBinding()
				.withInstanceMethods()
				.withRootObject(ctx)
				.build();
		return (Boolean) getParsedExpression().getValue(context);
	}

	private static List<ContainerWithType> collectContainers(V1PodSpec spec) {
		final var all = new ArrayList<ContainerWithType>();
		if (spec.getContainers() != null) {
			spec.getContainers().forEach(c ->
					all.add(new ContainerWithType(c, "standard")));
		}
		if (spec.getInitContainers() != null) {
			spec.getInitContainers().forEach(c ->
					all.add(new ContainerWithType(c, "init")));
		}
		if (spec.getEphemeralContainers() != null) {
			spec.getEphemeralContainers().forEach(ec ->
					all.add(new ContainerWithType(toV1Container(ec), "ephemeral")));
		}
		return all;
	}

	private static V1Container toV1Container(V1EphemeralContainer ec) {
		final var c = new V1Container();
		c.setName(ec.getName());
		c.setImage(ec.getImage());
		c.setCommand(ec.getCommand());
		c.setArgs(ec.getArgs());
		c.setSecurityContext(ec.getSecurityContext());
		c.setEnv(ec.getEnv());
		c.setVolumeMounts(ec.getVolumeMounts());
		c.setPorts(ec.getPorts());
		return c;
	}

	private Context buildContext(V1Pod pod, V1PodSpec spec, V1Container c, String containerType) {
		final var ctx = new Context();

		ctx.metadata = createMetadata(pod.getMetadata());

		ctx.spec = new Context.Spec();
		ctx.spec.hostPID = spec.getHostPID();
		ctx.spec.hostNetwork = spec.getHostNetwork();
		ctx.spec.hostIPC = spec.getHostIPC();
		ctx.spec.serviceAccountName = spec.getServiceAccountName();
		ctx.spec.automountServiceAccountToken = spec.getAutomountServiceAccountToken();

		ctx.securityContext = spec.getSecurityContext() != null
				? createPodSecurityContext(spec.getSecurityContext())
				: new Context.PodSecurityContext();

		ctx.container = buildContainerContext(c, containerType);

		return ctx;
	}

	private Context.Metadata createMetadata(V1ObjectMeta meta) {
		final var m = new Context.Metadata();
		if (meta != null) {
			m.name = meta.getName();
			m.namespace = meta.getNamespace();
			if (meta.getLabels() != null) {
				m.labels = meta.getLabels();
			}
			if (meta.getAnnotations() != null) {
				m.annotations = meta.getAnnotations();
			}
		}
		return m;
	}

	private Context.Container buildContainerContext(V1Container c, String containerType) {
		final var container = new Context.Container();
		container.image = new ImageData(c.getImage());
		container.name = c.getName();
		container.containerType = containerType;

		if (c.getCommand() != null) {
			container.command = c.getCommand();
		}
		if (c.getArgs() != null) {
			container.args = c.getArgs();
		}
		if (c.getPorts() != null) {
			container.ports = c.getPorts().stream()
					.map(V1ContainerPort::getContainerPort)
					.collect(Collectors.toList());
		}

		container.securityContext = c.getSecurityContext() != null
				? createContainerSecurityContext(c.getSecurityContext())
				: new Context.ContainerSecurityContext();

		if (container.securityContext.capabilities == null) {
			container.securityContext.capabilities = new Context.Capabilities();
		}

		return container;
	}

	private Context.PodSecurityContext createPodSecurityContext(V1PodSecurityContext securityContext) {
		final var ctx = new Context.PodSecurityContext();
		ctx.runAsUser = securityContext.getRunAsUser();
		ctx.runAsGroup = securityContext.getRunAsGroup();
		ctx.runAsNonRoot = securityContext.getRunAsNonRoot();
		ctx.fsGroup = securityContext.getFsGroup();
		if (securityContext.getSupplementalGroups() != null) {
			ctx.supplementalGroups = securityContext.getSupplementalGroups();
		}
		if (securityContext.getSeccompProfile() != null) {
			ctx.seccompProfileType = securityContext.getSeccompProfile().getType();
		}
		return ctx;
	}

	private Context.ContainerSecurityContext createContainerSecurityContext(V1SecurityContext securityContext) {
		final var ctx = new Context.ContainerSecurityContext();
		ctx.allowPrivilegeEscalation = securityContext.getAllowPrivilegeEscalation();
		ctx.privileged = securityContext.getPrivileged();
		ctx.readOnlyRootFilesystem = securityContext.getReadOnlyRootFilesystem();
		ctx.runAsUser = securityContext.getRunAsUser();
		ctx.runAsGroup = securityContext.getRunAsGroup();
		ctx.runAsNonRoot = securityContext.getRunAsNonRoot();
		ctx.procMount = securityContext.getProcMount();
		if (securityContext.getSeccompProfile() != null) {
			ctx.seccompProfileType = securityContext.getSeccompProfile().getType();
		}
		if (securityContext.getCapabilities() != null) {
			ctx.capabilities = createCapabilities(securityContext.getCapabilities());
		}
		return ctx;
	}

	private Context.Capabilities createCapabilities(V1Capabilities capabilities) {
		final var caps = new Context.Capabilities();
		if (capabilities.getAdd() != null) {
			caps.add = capabilities.getAdd();
		}
		if (capabilities.getDrop() != null) {
			caps.drop = capabilities.getDrop();
		}
		return caps;
	}

	private static class ContainerWithType {
		final V1Container container;
		final String type;

		ContainerWithType(V1Container container, String type) {
			this.container = container;
			this.type = type;
		}
	}
}
