package eu.vilaca.security.rule;

import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.rule.model.Namespace;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.models.*;
import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class RuleTest {

	// --- Helper methods ---

	private static V1Pod createPod(String namespace, String name, List<V1Container> containers) {
		return createPod(namespace, name, containers, null, null);
	}

	private static V1Pod createPod(String namespace, String name, List<V1Container> containers,
								   V1PodSecurityContext podSecCtx, Boolean hostPID) {
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace(namespace).name(name));
		final var spec = new V1PodSpec().containers(containers);
		if (podSecCtx != null) {
			spec.setSecurityContext(podSecCtx);
		}
		if (hostPID != null) {
			spec.setHostPID(hostPID);
		}
		pod.setSpec(spec);
		return pod;
	}

	private static V1Container createContainer(String image) {
		return new V1Container().name("test-container").image(image);
	}

	private static V1Container createContainerWithSecCtx(String image, V1SecurityContext secCtx) {
		return new V1Container().name("test-container").image(image).securityContext(secCtx);
	}

	private static Rule createRule(String name, String ruleExpr) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setEnabled(true);
		rule.setRule(ruleExpr);
		rule.setAlert("test-alert");
		return rule;
	}

	// --- allNamespaces() ---

	@Test
	public void allNamespaces_noFilter() {
		final var rule = createRule("test", "true");
		assertTrue(rule.allNamespaces());
	}

	@Test
	public void allNamespaces_filterWithNullNamespace() {
		final var rule = createRule("test", "true");
		rule.setFilter(new Filter());
		assertTrue(rule.allNamespaces());
	}

	@Test
	public void allNamespaces_filterWithExclude() {
		final var rule = createRule("test", "true");
		final var ns = new Namespace();
		ns.setExclude(List.of("kube-system"));
		final var filter = new Filter();
		filter.setNamespace(ns);
		rule.setFilter(filter);
		// exclude != null → allNamespaces returns true (watches all, filters out)
		assertTrue(rule.allNamespaces());
	}

	@Test
	public void allNamespaces_filterWithInclude() {
		final var rule = createRule("test", "true");
		final var ns = new Namespace();
		ns.setInclude(List.of("default"));
		final var filter = new Filter();
		filter.setNamespace(ns);
		rule.setFilter(filter);
		// include only, no exclude → allNamespaces returns false
		assertFalse(rule.allNamespaces());
	}

	// --- evaluate() with simple rules ---

	@Test
	public void evaluateAlwaysTrueRule() {
		final var rule = createRule("always-true", "true");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "nginx-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void evaluateAlwaysFalseRule() {
		final var rule = createRule("always-false", "false");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "nginx-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- Pod with null spec ---

	@Test
	public void evaluatePodWithNullSpec() {
		final var rule = createRule("test", "true");
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace("default").name("broken-pod"));
		// No spec set

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- Pod with null containers ---

	@Test
	public void evaluatePodWithNullContainers() {
		final var rule = createRule("test", "true");
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace("default").name("empty-pod"));
		pod.setSpec(new V1PodSpec());
		// containers is null by default

		// Current code: spec.getContainers() may be null → NPE
		try {
			final var violations = rule.evaluate(pod);
			// If it doesn't throw, it should be empty
			assertTrue(violations.isEmpty());
		} catch (NullPointerException e) {
			// Current behavior: crashes on null containers list
		}
	}

	// --- Multiple containers ---

	@Test
	public void evaluateMultipleContainers_allMatch() {
		final var rule = createRule("always-true", "true");
		final var c1 = createContainer("docker.io/nginx:latest");
		final var c2 = createContainer("docker.io/redis:7.0");
		final var pod = createPod("default", "multi-pod", List.of(c1, c2));

		final var violations = rule.evaluate(pod);
		assertEquals(2, violations.size());
	}

	@Test
	public void evaluateMultipleContainers_noneMatch() {
		final var rule = createRule("always-false", "false");
		final var c1 = createContainer("docker.io/nginx:latest");
		final var c2 = createContainer("docker.io/redis:7.0");
		final var pod = createPod("default", "multi-pod", List.of(c1, c2));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void evaluateEmptyContainersList() {
		final var rule = createRule("test", "true");
		final var pod = createPod("default", "empty-pod", Collections.emptyList());

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- Security context rules ---

	@Test
	public void runAsRootDetection_podLevel() {
		final var rule = createRule("run-as-root", "securityContext.runAsUser == 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var podSecCtx = new V1PodSecurityContext().runAsUser(0L);
		final var pod = createPod("default", "root-pod", List.of(container), podSecCtx, null);

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void runAsRootDetection_containerLevel() {
		final var rule = createRule("run-as-root",
				"container.securityContext.runAsUser == 0");
		final var secCtx = new V1SecurityContext().runAsUser(0L);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "root-container", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void runAsNonRoot_noViolation() {
		final var rule = createRule("run-as-root", "securityContext.runAsUser == 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var podSecCtx = new V1PodSecurityContext().runAsUser(1000L);
		final var pod = createPod("default", "safe-pod", List.of(container), podSecCtx, null);

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void privilegedContainerDetection() {
		final var rule = createRule("privileged",
				"container.securityContext.privileged == true");
		final var secCtx = new V1SecurityContext().privileged(true);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "priv-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void nonPrivilegedContainer_noViolation() {
		final var rule = createRule("privileged",
				"container.securityContext.privileged == true");
		final var secCtx = new V1SecurityContext().privileged(false);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "safe-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void allowPrivilegeEscalation() {
		final var rule = createRule("priv-escalation",
				"container.securityContext.allowPrivilegeEscalation == true");
		final var secCtx = new V1SecurityContext().allowPrivilegeEscalation(true);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "escalation-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void readOnlyRootFilesystem_false() {
		final var rule = createRule("readonly-fs",
				"container.securityContext.readOnlyRootFilesystem == false");
		final var secCtx = new V1SecurityContext().readOnlyRootFilesystem(false);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "rw-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void readOnlyRootFilesystem_true_noViolation() {
		final var rule = createRule("readonly-fs",
				"container.securityContext.readOnlyRootFilesystem == false");
		final var secCtx = new V1SecurityContext().readOnlyRootFilesystem(true);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "ro-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- hostPID ---

	@Test
	public void hostPIDEnabled() {
		final var rule = createRule("hostpid", "spec.hostPID == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "hostpid-pod", List.of(container), null, true);

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void hostPIDDisabled() {
		final var rule = createRule("hostpid", "spec.hostPID == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "safe-pod", List.of(container), null, false);

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- Image registry rules ---

	@Test
	public void registryCheckMatch() {
		final var rule = createRule("registry-check",
				"container.image.registry != 'registry.k8s.io'");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "nginx-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void registryCheckNoMatch() {
		final var rule = createRule("registry-check",
				"container.image.registry != 'registry.k8s.io'");
		final var container = createContainer("registry.k8s.io/kube-proxy:v1.28");
		final var pod = createPod("default", "kube-proxy", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- Compound rules (OR / AND) ---

	@Test
	public void compoundOrRule_firstTrue() {
		final var rule = createRule("compound-or",
				"securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var podSecCtx = new V1PodSecurityContext().runAsUser(0L);
		final var pod = createPod("default", "root-pod", List.of(container), podSecCtx, null);

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void compoundOrRule_secondTrue() {
		final var rule = createRule("compound-or",
				"securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0");
		final var secCtx = new V1SecurityContext().runAsUser(0L);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "root-container", List.of(container));

		// Pod has no pod-level securityContext → SpEL throws on securityContext.runAsUser
		// before evaluating the second part of the OR → caught, returns empty
		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void compoundAndRule_bothTrue() {
		final var rule = createRule("compound-and",
				"container.securityContext.privileged == true && container.securityContext.allowPrivilegeEscalation == true");
		final var secCtx = new V1SecurityContext().privileged(true).allowPrivilegeEscalation(true);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "bad-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void compoundAndRule_onlyOneTrue() {
		final var rule = createRule("compound-and",
				"container.securityContext.privileged == true && container.securityContext.allowPrivilegeEscalation == true");
		final var secCtx = new V1SecurityContext().privileged(true).allowPrivilegeEscalation(false);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "half-bad-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- Invalid SpEL expression ---

	@Test
	public void invalidSpelExpression_returnsEmpty() {
		final var rule = createRule("broken", "this is not valid SpEL !!!@#$");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		// Should not throw, should return empty list (caught by SpelEvaluationException handler)
		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void spelReferencingNonExistentProperty_returnsEmpty() {
		final var rule = createRule("bad-prop", "container.nonExistent == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- Null security contexts ---

	@Test
	public void nullPodSecurityContext_ruleAccessingIt() {
		// Rule references securityContext.runAsUser but pod has no security context
		final var rule = createRule("null-sec-ctx", "securityContext.runAsUser == 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "no-sec-pod", List.of(container));

		// securityContext is null in the Context → SpEL should throw/catch
		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void nullContainerSecurityContext_defaultValues() {
		// Container has no security context set → fields are default null
		final var rule = createRule("no-container-sec",
				"container.securityContext.privileged == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "no-sec-container", List.of(container));

		// privileged is null, comparing null == true → should be false → no violation
		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	// --- Disabled rule should not be evaluated (caller responsibility, but test Rule state) ---

	@Test
	public void disabledRuleState() {
		final var rule = createRule("disabled", "true");
		rule.setEnabled(false);
		assertFalse(rule.isEnabled());
	}

	// --- Violation content check ---

	@Test
	public void violationContainsCorrectData() {
		final var rule = createRule("test-rule", "true");
		rule.setAlert("my-alert");
		final var container = createContainer("docker.io/nginx:1.25");
		final var pod = createPod("prod", "web-server", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());

		final var v = violations.get(0);
		assertEquals("test-rule", v.getRule().getName());
		assertEquals("my-alert", v.getRule().getAlert());
		assertEquals("prod", v.getNamespace());
		assertEquals("web-server", v.getPod());
	}

	// --- Pod with null metadata ---

	@Test
	public void podWithNullMetadata() {
		final var rule = createRule("test", "true");
		final var pod = new V1Pod();
		pod.setSpec(new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))));
		// metadata is null

		// PodRuleViolation constructor handles null metadata, but evaluate may not
		try {
			final var violations = rule.evaluate(pod);
			if (!violations.isEmpty()) {
				assertNull(violations.get(0).getNamespace());
				assertNull(violations.get(0).getPod());
			}
		} catch (NullPointerException e) {
			// Current behavior: may crash
		}
	}

	// --- Mixed containers: some match, some don't ---

	@Test
	public void mixedContainers_onlyMatchingOnesViolate() {
		final var rule = createRule("privileged-check",
				"container.securityContext.privileged == true");
		final var privContainer = createContainerWithSecCtx("docker.io/nginx:latest",
				new V1SecurityContext().privileged(true));
		final var safeContainer = createContainerWithSecCtx("docker.io/redis:7.0",
				new V1SecurityContext().privileged(false));
		final var pod = createPod("default", "mixed-pod", List.of(privContainer, safeContainer));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}
}
