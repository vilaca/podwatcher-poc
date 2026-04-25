package eu.vilaca.security.rule;

import eu.vilaca.security.observability.Metrics;
import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.violation.PodRuleViolation;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

import java.util.Collections;
import java.util.List;

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
}
