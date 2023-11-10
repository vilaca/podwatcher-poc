package eu.vilaca.rule;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@Data
public class AllowList {
	private List<String> allowed;

	public boolean isAllowed(String candidate) {
		return allowed == null || allowed.isEmpty() || allowed.contains(candidate);
	}
}
