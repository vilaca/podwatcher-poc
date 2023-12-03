package eu.vilaca.security.service;

import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.violation.RuleViolation;

import java.util.List;

public interface WatcherService {
	List<RuleViolation> watch(List<Rule> rules);
}