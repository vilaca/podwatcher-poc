package eu.vilaca.security.alert.model;

import lombok.Data;

import java.util.List;

@Data
public class AlertTemplate {
	private String name;
	private String env;
	private String group;
	private List<String> labels;
}
