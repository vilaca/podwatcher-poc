package eu.vilaca.security.service;

import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.violation.PodRuleViolation;

import java.util.List;

public interface WatcherService {
	List<PodRuleViolation> watch(List<Rule> rules);
}
