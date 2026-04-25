package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Rule;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
public class PodRuleViolation {
	private ImageData imageData;
	private Rule rule;
	private String namespace;
	private String pod;

	public PodRuleViolation(Rule rule, String namespace, String containerName, String image) {
		this.imageData = new ImageData(image);
		this.rule = rule;
		this.namespace = namespace;
		this.pod = containerName;
	}

	private static void addLabel(HashMap<String, String> labels, String name, String value) {
		if (value != null) {
			labels.put(name, value);
		}
	}

	public Map<String, String> createLabels() {
		final var labels = new HashMap<String, String>();
		addLabel(labels, "rule", this.rule.getName());
		addLabel(labels, "namespace", this.namespace);
		addLabel(labels, "pod", this.pod);
		addLabel(labels, "image", this.imageData.pretty());
		addLabel(labels, "severity", this.rule.getSeverity());
		return labels;
	}
}
