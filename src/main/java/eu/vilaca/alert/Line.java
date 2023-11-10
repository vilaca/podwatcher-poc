package eu.vilaca.alert;

import eu.vilaca.violation.PodRuleViolation;
import lombok.Data;

import java.util.Map;

@Data
public class Line {
	private Map<String, String> labels;
	private String endsAt;

	Line(PodRuleViolation violation) {
		labels = violation.createLabels();
	}
}
