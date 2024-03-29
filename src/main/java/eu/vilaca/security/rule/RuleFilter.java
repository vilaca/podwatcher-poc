package eu.vilaca.security.rule;

import lombok.Data;

import java.util.List;

@Data
public class RuleFilter {
	private List<String> include;
	private List<String> exclude;

	public boolean filter(String candidate) {
		if (filterActive(include) && !include.contains(candidate)) {
			return false;
		}
		return !filterActive(exclude) || !exclude.contains(candidate);
	}

	private boolean filterActive(List<String> rules) {
		return rules != null && !rules.isEmpty();
	}
}