package eu.vilaca.security.alert.model;

import lombok.Data;

import java.util.Map;

@Data
public class MessageLine {
	private Map<String, String> labels;
	private String endsAt;

	MessageLine(Map<String, String> labels) {
		this.labels = labels;
	}
}
