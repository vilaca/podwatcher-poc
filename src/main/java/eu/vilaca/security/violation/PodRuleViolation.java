package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Rule;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
public class PodRuleViolation {
//	private ImageData imageData;
//	private Rule rule;
//	private String namespace;
//	private String pod;
//
//	public PodRuleViolation(RuleViolation rv) {
//		this.rule = rv.getRule();
//		this.imageData = rv.getCtx().container.image;
//		this.namespace = rv.getCtx().namespace;
//		this.pod = rv.getCtx().container.podName;
//	}
//
//	private static void addLabel(HashMap<String, String> labels, String name, String value) {
//		if (value != null) {
//			labels.put(name, value);
//		}
//	}
//
//	public Map<String, String> createLabels() {
//		final var labels = new HashMap<String, String>();
//		addLabel(labels, "rule", this.rule.getName());
//		addLabel(labels, "namespace", this.namespace);
//		addLabel(labels, "pod", this.pod);
//		addLabel(labels, "image", this.imageData.pretty());
//		return labels;
//	}
}
