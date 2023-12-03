package eu.vilaca.security.rule;

import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.violation.ImageData;
import eu.vilaca.security.violation.RuleViolation;
import io.kubernetes.client.openapi.models.V1ClusterRole;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1PodSecurityContext;
import io.kubernetes.client.openapi.models.V1SecurityContext;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Log4j2
@Data
public class Rule {

	private String name;
	private boolean enabled;
	private Filter filter;
	private String rule;
	private String alert;
	private String target;
	private Map<String, String> labels;

	public boolean allNamespaces() {
		return this.filter == null
				|| this.filter.getNamespace() == null
				|| this.filter.getNamespace().getExclude() != null;
	}

	public List<RuleViolation> evaluate(V1Pod pod) {
		final var spec = pod.getSpec();
		if (spec == null
				|| pod.getMetadata() == null
				|| spec.getContainers() == null) {
			return Collections.emptyList();
		}
		try {
			final var violations = new ArrayList<RuleViolation>();
			spec.getContainers()
					.forEach(container -> {
								final var ctx = buildContext(pod, container);
								if (evaluateRule(ctx)) {
									violations.add(new RuleViolation(ctx));
								}
							}
					);
			return violations;
		} catch (SpelEvaluationException se) {
			log.error("Can't evaluate rule {}. {}", this.name, se.getMessage());
		} catch (Exception ex) {
			log.error("Can't evaluate rule {}.", this.name, ex);
		}
		return Collections.emptyList();
	}

	public List<RuleViolation> evaluate(V1ClusterRole cr) {
		final var crRules = cr.getRules();
		if (crRules == null) {
			return Collections.emptyList();
		}
		final var name = cr.getMetadata().getName();
		try {
			final var violations = new ArrayList<RuleViolation>();
			crRules.stream()
					.filter(v1PolicyRule -> v1PolicyRule.getResources() != null)
					.forEach(
							policy -> policy.getResources().forEach(
									res -> policy.getVerbs().forEach(
											verb -> {
												final var ctx = buildContext(this, name, res, verb);
												if (evaluateRule(ctx)) {
													violations.add(new RuleViolation(ctx));
												}
											}
									)
							)
					);
			return violations;
		} catch (SpelEvaluationException se) {
			log.error("Can't evaluate rule {}. {}", this.name, se.getMessage());
		} catch (Exception ex) {
			log.error("Can't evaluate rule {}.", this.name, ex);
		}
		return Collections.emptyList();
	}

	private Context buildContext(Rule rule, String name, String res, String verb) {
		final var ctx = new Context();
		ctx.rule = rule;
		ctx.role = new Context.Role();
		ctx.role.name = name;
		ctx.role.resource = res;
		ctx.role.verb = verb;
		return ctx;
	}

	private Boolean evaluateRule(Context ctx) {
		final var parser = new SpelExpressionParser();
		final var context = new StandardEvaluationContext(ctx);
		final var exp = parser.parseExpression(rule);
		return (Boolean) exp.getValue(context);
	}

	private Context buildContext(V1Pod pod, V1Container c) {
		final var spec = pod.getSpec();
		final var ctx = new Context();
		ctx.spec = new Context.Spec();
		ctx.spec.hostPID = spec.getHostPID();
		if (spec.getSecurityContext() != null) {
			ctx.securityContext = createSecurityContext(spec.getSecurityContext());
		}
		ctx.container = new Context.Container();
		ctx.container.podName = pod.getMetadata().getName();
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
