package eu.vilaca.security.rule.model;

import lombok.Data;
import lombok.Setter;

import java.util.List;

@Data
@Setter
public class Namespace {
	private List<String> include;
	private List<String> exclude;
}
