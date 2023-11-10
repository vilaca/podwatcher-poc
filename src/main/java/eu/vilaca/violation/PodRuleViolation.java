package eu.vilaca.violation;

import eu.vilaca.rule.PodWatcherRule;
import lombok.Builder;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Builder
@Data
public class PodRuleViolation {
	private ImageData imageData;
	private PodWatcherRule rule;
	private String namespace;
	private String pod;

	private static void addLabel(HashMap<String, String> labels, String name, String value) {
		if (value != null) {
			labels.put(name, value);
		}
	}

	public Map<String, String> createLabels() {
		final var labels = new HashMap<String, String>();
		addLabel(labels, "Rule", this.rule.getName());
		addLabel(labels, "Namespace", this.namespace);
		addLabel(labels, "Pod", this.pod);
		addLabel(labels, "Image", this.imageData.pretty());
		return labels;
	}
}
