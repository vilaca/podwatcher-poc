package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Rule;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1Pod;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
public class PodRuleViolation {
	private ImageData imageData;
	private Rule rule;
	private String namespace;
	private String pod;

	public PodRuleViolation(Rule rule, V1Pod pod, V1Container c) {
		this.imageData = new ImageData(c.getImage());
		this.rule = rule;
		this.namespace = pod.getMetadata() == null ? null : pod.getMetadata().getNamespace();
		this.pod = pod.getMetadata() == null ? null : pod.getMetadata().getName();
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
		return labels;
	}
}
