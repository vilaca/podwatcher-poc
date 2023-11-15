package eu.vilaca.security.rule;

import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.violation.ImageData;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodSecurityContext;
import io.kubernetes.client.openapi.models.V1PodSpec;
import io.kubernetes.client.openapi.models.V1SecurityContext;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

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

	public boolean allNamespaces() {
		return this.filter == null || this.filter.getNamespaces() == null
				|| this.filter.getNamespaces().getExclude() != null;
	}

	public List<PodRuleViolation> evaluate(V1Pod pod) {
		final var spec = pod.getSpec();
		if (spec != null) {
			try {
				return spec.getContainers().stream()
						.filter(c -> evaluateRule(buildContext(spec, c)))
						.map(c -> new PodRuleViolation(this, pod, c))
						.collect(Collectors.toList());
			} catch (SpelEvaluationException se) {
				log.error("Can't evaluate rule {}. {}", this.name, se.getMessage());
			} catch (Exception ex) {
				log.error("Can't evaluate rule {}.", this.name, ex);
			}
		} else {
			log.warn("Unexpected/Corrupt cluster data. Can't evaluate rule {}", this.name);
		}
		return Collections.emptyList();
	}

	private Boolean evaluateRule(Context ctx) {
		final var parser = new SpelExpressionParser();
		final var context = new StandardEvaluationContext(ctx);
		final var exp = parser.parseExpression(rule);
		return (Boolean) exp.getValue(context);
	}

	private Context buildContext(V1PodSpec spec, V1Container c) {
		final var ctx = new Context();
		ctx.spec = new Context.Spec();
		ctx.spec.hostPID = spec.getHostPID();
		if (spec.getSecurityContext() != null) {
			ctx.securityContext = createSecurityContext(spec.getSecurityContext());
		}
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData(c.getImage());
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		if (c.getSecurityContext() != null) {
			ctx.container.securityContext = createSecurityContext(c.getSecurityContext());
		}
		return ctx;
	}

	private Context.PodSecurityContext createSecurityContext(V1PodSecurityContext securityContext) {
		final var ctx = new Context.PodSecurityContext();
		ctx.runAsUser = securityContext.getRunAsUser();
		ctx.runAsGroup = securityContext.getRunAsGroup();
		ctx.runAsNonRoot = securityContext.getRunAsNonRoot();
		return ctx;
	}

	private Context.ContainerSecurityContext createSecurityContext(V1SecurityContext securityContext) {
		final var ctx = new Context.ContainerSecurityContext();
		ctx.allowPrivilegeEscalation = securityContext.getAllowPrivilegeEscalation();
		ctx.privileged = securityContext.getPrivileged();
		ctx.readOnlyRootFilesystem = securityContext.getReadOnlyRootFilesystem();
		ctx.runAsUser = securityContext.getRunAsUser();
		ctx.runAsGroup = securityContext.getRunAsGroup();
		ctx.runAsNonRoot = securityContext.getRunAsNonRoot();
		return ctx;
	}
}
