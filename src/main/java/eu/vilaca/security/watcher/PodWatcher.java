package eu.vilaca.security.watcher;

import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.violation.RuleViolation;

import java.util.List;

public interface PodWatcher {
	List<RuleViolation> evaluate(Rule rule);
}
