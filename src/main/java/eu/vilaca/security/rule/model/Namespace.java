package eu.vilaca.security.rule.model;

import lombok.Data;

import java.util.List;

@Data
public class Namespace {
	private List<String> include;
	private List<String> exclude;
}
