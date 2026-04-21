package eu.vilaca.security;

import eu.vilaca.security.alert.model.AlertTemplate;
import eu.vilaca.security.rule.Rule;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class ConfigValidationTest {

	private static Rule createRule(String name, String ruleExpr, String alert) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setEnabled(true);
		rule.setRule(ruleExpr);
		rule.setAlert(alert);
		return rule;
	}

	private static AlertTemplate createTemplate(String name, List<String> labels) {
		final var template = new AlertTemplate();
		template.setName(name);
		template.setLabels(labels);
		return template;
	}

	// --- Valid config ---

	@Test
	public void validConfig_noErrors() {
		final var template = createTemplate("my-alert", List.of("rule", "namespace"));
		final var rule = createRule("my-rule", "true", "my-alert");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("my-alert", template));
		assertTrue(errors.isEmpty());
	}

	@Test
	public void multipleValidRulesAndTemplates() {
		final var t1 = createTemplate("alert-a", List.of("rule"));
		final var t2 = createTemplate("alert-b", List.of("namespace"));
		final var r1 = createRule("rule-1", "true", "alert-a");
		final var r2 = createRule("rule-2", "false", "alert-b");
		final var errors = PodWatcherApp.validate(List.of(r1, r2), Map.of("alert-a", t1, "alert-b", t2));
		assertTrue(errors.isEmpty());
	}

	// --- Rule with null rule expression ---

	@Test
	public void ruleWithNullExpression_fails() {
		final var template = createTemplate("alert", List.of("rule"));
		final var rule = createRule("bad-rule", null, "alert");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("alert", template));
		assertEquals(1, errors.size());
		assertTrue(errors.get(0).contains("bad-rule"));
		assertTrue(errors.get(0).contains("SpEL"));
	}

	@Test
	public void ruleWithBlankExpression_fails() {
		final var template = createTemplate("alert", List.of("rule"));
		final var rule = createRule("blank-rule", "   ", "alert");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("alert", template));
		assertEquals(1, errors.size());
		assertTrue(errors.get(0).contains("blank-rule"));
	}

	// --- Rule with null alert reference ---

	@Test
	public void ruleWithNullAlert_fails() {
		final var template = createTemplate("alert", List.of("rule"));
		final var rule = createRule("no-alert-rule", "true", null);
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("alert", template));
		assertEquals(1, errors.size());
		assertTrue(errors.get(0).contains("no-alert-rule"));
		assertTrue(errors.get(0).contains("alert template reference"));
	}

	@Test
	public void ruleWithBlankAlert_fails() {
		final var template = createTemplate("alert", List.of("rule"));
		final var rule = createRule("blank-alert-rule", "true", "  ");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("alert", template));
		assertEquals(1, errors.size());
	}

	// --- Rule references nonexistent template ---

	@Test
	public void ruleReferencesUnknownTemplate_fails() {
		final var template = createTemplate("existing-alert", List.of("rule"));
		final var rule = createRule("orphan-rule", "true", "nonexistent-alert");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("existing-alert", template));
		assertEquals(1, errors.size());
		assertTrue(errors.get(0).contains("orphan-rule"));
		assertTrue(errors.get(0).contains("nonexistent-alert"));
	}

	// --- Template with null labels ---

	@Test
	public void templateWithNullLabels_fails() {
		final var template = createTemplate("bad-template", null);
		final var rule = createRule("rule", "true", "bad-template");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("bad-template", template));
		assertEquals(1, errors.size());
		assertTrue(errors.get(0).contains("bad-template"));
		assertTrue(errors.get(0).contains("labels"));
	}

	@Test
	public void templateWithEmptyLabels_fails() {
		final var template = createTemplate("empty-labels", List.of());
		final var rule = createRule("rule", "true", "empty-labels");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("empty-labels", template));
		assertEquals(1, errors.size());
		assertTrue(errors.get(0).contains("empty-labels"));
	}

	// --- Template with null name ---

	@Test
	public void templateWithNullName_fails() {
		final var template = createTemplate(null, List.of("rule"));
		final var rule = createRule("rule", "true", "null");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("null-key", template));
		assertFalse(errors.isEmpty());
	}

	@Test
	public void templateWithBlankName_fails() {
		final var template = createTemplate("  ", List.of("rule"));
		final var rule = createRule("rule", "true", "  ");
		final var errors = PodWatcherApp.validate(List.of(rule), Map.of("  ", template));
		assertFalse(errors.isEmpty());
	}

	// --- Multiple errors reported at once ---

	@Test
	public void multipleErrors_allReported() {
		final var template = createTemplate("alert", null); // bad labels
		final var r1 = createRule("rule1", null, "alert"); // bad expression
		final var r2 = createRule("rule2", "true", "missing"); // bad reference
		final var errors = PodWatcherApp.validate(List.of(r1, r2), Map.of("alert", template));
		assertEquals(3, errors.size());
	}
}
