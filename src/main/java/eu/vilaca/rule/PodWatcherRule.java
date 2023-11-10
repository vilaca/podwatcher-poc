package eu.vilaca.rule;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
public class PodWatcherRule {

	private String name;
	private RuleFilter namespace;

	// allowList
	private AllowList imageName;
	private LogicOperation operation;
	private AllowList repository;
	private AllowList sha;
	private AllowList tag;

	public boolean allNamespaces() {
		return namespace == null || namespace.getInclude() == null
				|| namespace.getInclude().contains("")
				|| namespace.getInclude().contains("*")
				|| namespace.getInclude().contains(null)
				|| namespace.getInclude().isEmpty();
	}

	public List<String> include() {
		return namespace == null || namespace.getInclude() == null ? List.of() : namespace.getInclude();
	}

	public List<String> exclude() {
		return namespace == null || namespace.getExclude() == null ? List.of() : namespace.getExclude();
	}

	@Builder
	@Data
	public static class PodRuleMetadata {
		private String name;
	}
}
