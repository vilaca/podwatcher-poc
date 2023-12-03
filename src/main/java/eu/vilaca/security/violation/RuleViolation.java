package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Context;
import lombok.Data;

@Data
public class RuleViolation {
	private final Context ctx;
}
