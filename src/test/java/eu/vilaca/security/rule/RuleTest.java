package eu.vilaca.security.rule;

import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.rule.model.Namespace;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.models.*;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

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

	private static V1Pod createPodWithSpec(String namespace, String name, V1PodSpec spec) {
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace(namespace).name(name));
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

	private static Rule createRuleWithSeverity(String name, String ruleExpr, String severity) {
		final var rule = createRule(name, ruleExpr);
		rule.setSeverity(severity);
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
		// exclude != null -> allNamespaces returns true (watches all, filters out)
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
		// include only, no exclude -> allNamespaces returns false
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

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
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

		// Pod has no pod-level securityContext. With null safety fix, securityContext is
		// always initialized so securityContext.runAsUser is null. null == 0 is false,
		// then the right side (container.securityContext.runAsUser == 0) is true.
		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
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
		// Rule references securityContext.runAsUser but pod has no security context.
		// With null safety fix, securityContext is always initialized so
		// securityContext.runAsUser is null, and null == 0 evaluates to false.
		final var rule = createRule("null-sec-ctx", "securityContext.runAsUser == 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "no-sec-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void nullContainerSecurityContext_defaultValues() {
		// Container has no security context set -> fields are default null
		final var rule = createRule("no-container-sec",
				"container.securityContext.privileged == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "no-sec-container", List.of(container));

		// privileged is null, comparing null == true -> should be false -> no violation
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

		final var violations = rule.evaluate(pod);
		if (!violations.isEmpty()) {
			assertNull(violations.get(0).getNamespace());
			assertNull(violations.get(0).getPod());
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

	// ================================================================
	// Phase 1 — Null safety tests
	// ================================================================

	@Test
	public void nullPodSecurityContext_compoundOr_rightSideMatches() {
		// Pod has no pod-level securityContext, container has runAsUser == 0.
		// The || expression should evaluate: left side (null == 0 -> false), right side (0 == 0 -> true).
		final var rule = createRule("compound-or",
				"securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0");
		final var secCtx = new V1SecurityContext().runAsUser(0L);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "root-container", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void nullPodSecurityContext_compoundOr_neitherMatches() {
		// Pod has no pod-level securityContext, container has runAsUser == 1000.
		// Both sides false -> no violation.
		final var rule = createRule("compound-or",
				"securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0");
		final var secCtx = new V1SecurityContext().runAsUser(1000L);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "safe-container", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void nullPodSecurityContext_compoundAnd_safeEvaluation() {
		// && with null intermediate: securityContext.runAsNonRoot is null -> null == true is false -> short-circuit
		final var rule = createRule("compound-and",
				"securityContext.runAsNonRoot == true && container.securityContext.privileged == true");
		final var secCtx = new V1SecurityContext().privileged(true);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertTrue(violations.isEmpty());
	}

	@Test
	public void allContextSubObjectsAlwaysInitialized() {
		// Bare minimum pod with no security contexts at any level.
		// Verify the rule can access all intermediate objects without error.
		final var rule = createRule("deep-access",
				"securityContext.runAsUser == null && container.securityContext.privileged == null && spec.hostPID == null");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "bare-pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	// ================================================================
	// Phase 2 — Instance method tests
	// ================================================================

	@Test
	public void spelStringStartsWith() {
		final var rule = createRule("starts-with", "container.image.registry.startsWith('docker')");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void spelStringStartsWith_noMatch() {
		final var rule = createRule("starts-with", "container.image.registry.startsWith('docker')");
		final var container = createContainer("ghcr.io/org/app:v1");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void spelStringContains() {
		final var rule = createRule("contains", "container.image.name.contains('ngi')");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void spelStringContains_noMatch() {
		final var rule = createRule("contains", "container.image.name.contains('ngi')");
		final var container = createContainer("docker.io/redis:7.0");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void spelStringToLowerCase() {
		final var rule = createRule("lower", "container.image.tag.toLowerCase() == 'latest'");
		final var container = createContainer("docker.io/nginx:LATEST");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void spelStringMatches_regex() {
		final var rule = createRule("regex", "container.image.tag.matches('v[0-9]+\\.[0-9]+')");
		final var container = createContainer("docker.io/app:v1.25");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void spelStringMatches_regex_noMatch() {
		final var rule = createRule("regex", "container.image.tag.matches('v[0-9]+\\.[0-9]+')");
		final var container = createContainer("docker.io/app:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void spelInlineListContains_allowlist() {
		// Disallowed registry: not in the inline allowlist
		final var rule = createRule("allowlist",
				"!{'registry.k8s.io', 'docker.io', 'ghcr.io'}.contains(container.image.registry)");
		final var container = createContainer("quay.io/prometheus/node-exporter:v1");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void spelInlineListContains_allowlist_noViolation() {
		final var rule = createRule("allowlist",
				"!{'registry.k8s.io', 'docker.io', 'ghcr.io'}.contains(container.image.registry)");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void spelStringLength() {
		final var rule = createRule("long-tag", "container.image.tag.length() > 10");
		final var container = createContainer("docker.io/app:this-is-a-very-long-tag");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	// ================================================================
	// Phase 3 — Expanded Context schema tests
	// ================================================================

	@Test
	public void hostNetworkEnabled_detected() {
		final var rule = createRule("hostnet", "spec.hostNetwork == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var spec = new V1PodSpec().containers(List.of(container)).hostNetwork(true);
		final var pod = createPodWithSpec("default", "pod", spec);

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void hostNetworkDisabled_noViolation() {
		final var rule = createRule("hostnet", "spec.hostNetwork == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var spec = new V1PodSpec().containers(List.of(container)).hostNetwork(false);
		final var pod = createPodWithSpec("default", "pod", spec);

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void hostIPCEnabled_detected() {
		final var rule = createRule("hostipc", "spec.hostIPC == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var spec = new V1PodSpec().containers(List.of(container)).hostIPC(true);
		final var pod = createPodWithSpec("default", "pod", spec);

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void serviceAccountName_match() {
		final var rule = createRule("sa-check", "spec.serviceAccountName == 'cluster-admin'");
		final var container = createContainer("docker.io/nginx:latest");
		final var spec = new V1PodSpec().containers(List.of(container)).serviceAccountName("cluster-admin");
		final var pod = createPodWithSpec("default", "pod", spec);

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void automountServiceAccountToken_true() {
		final var rule = createRule("automount", "spec.automountServiceAccountToken != false");
		final var container = createContainer("docker.io/nginx:latest");
		final var spec = new V1PodSpec().containers(List.of(container)).automountServiceAccountToken(true);
		final var pod = createPodWithSpec("default", "pod", spec);

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void capabilitiesDropAll_detected() {
		// Container that does NOT drop ALL capabilities -> violation
		final var rule = createRule("drop-all",
				"!container.securityContext.capabilities.drop.contains('ALL')");
		final var secCtx = new V1SecurityContext()
				.capabilities(new V1Capabilities().drop(List.of("NET_RAW")));
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void capabilitiesDropAll_noViolation() {
		final var rule = createRule("drop-all",
				"!container.securityContext.capabilities.drop.contains('ALL')");
		final var secCtx = new V1SecurityContext()
				.capabilities(new V1Capabilities().drop(List.of("ALL")));
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void capabilitiesAddNetAdmin_detected() {
		final var rule = createRule("net-admin",
				"container.securityContext.capabilities.add.contains('NET_ADMIN')");
		final var secCtx = new V1SecurityContext()
				.capabilities(new V1Capabilities().add(List.of("NET_ADMIN", "SYS_TIME")));
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void capabilitiesEmpty_noViolation() {
		// No capabilities set at all -> add/drop are empty lists -> .contains() returns false
		final var rule = createRule("net-admin",
				"container.securityContext.capabilities.add.contains('NET_ADMIN')");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void seccompProfileType_unconfined() {
		final var rule = createRule("seccomp",
				"container.securityContext.seccompProfileType == 'Unconfined'");
		final var secCtx = new V1SecurityContext()
				.seccompProfile(new V1SeccompProfile().type("Unconfined"));
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void containerName_access() {
		final var rule = createRule("name-check", "container.name == 'sidecar'");
		final var container = new V1Container().name("sidecar").image("docker.io/envoy:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void containerCommand_access() {
		final var rule = createRule("cmd-check", "container.command.contains('/bin/sh')");
		final var container = new V1Container().name("c").image("docker.io/alpine:latest")
				.command(List.of("/bin/sh", "-c", "echo hello"));
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void podLabels_access() {
		final var rule = createRule("label-check", "metadata.labels.containsKey('app')");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));
		pod.getMetadata().setLabels(Map.of("app", "web", "env", "prod"));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void podAnnotations_access() {
		final var rule = createRule("annotation-check",
				"metadata.annotations.containsKey('iam.amazonaws.com/role')");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));
		pod.getMetadata().setAnnotations(Map.of("iam.amazonaws.com/role", "admin"));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void podMetadata_namespace() {
		final var rule = createRule("ns-check", "metadata.namespace == 'kube-system'");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("kube-system", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void emptyCollections_neverNull() {
		// Verify collections default to empty, not null, even with bare-minimum pod
		final var rule = createRule("empty-check",
				"container.securityContext.capabilities.add.size() == 0 " +
						"&& container.securityContext.capabilities.drop.size() == 0 " +
						"&& container.command.size() == 0 " +
						"&& container.args.size() == 0 " +
						"&& container.ports.size() == 0 " +
						"&& metadata.labels.size() == 0 " +
						"&& metadata.annotations.size() == 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	// ================================================================
	// Phase 4 — Init & ephemeral container tests
	// ================================================================

	@Test
	public void initContainer_privileged_detected() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var standard = createContainer("docker.io/nginx:latest");
		final var init = createContainerWithSecCtx("docker.io/init:latest",
				new V1SecurityContext().privileged(true));
		init.setName("init-container");
		final var spec = new V1PodSpec().containers(List.of(standard)).initContainers(List.of(init));
		final var pod = createPodWithSpec("default", "pod", spec);

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void initContainer_safe_noViolation() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var standard = createContainer("docker.io/nginx:latest");
		final var init = createContainerWithSecCtx("docker.io/init:latest",
				new V1SecurityContext().privileged(false));
		init.setName("init-container");
		final var spec = new V1PodSpec().containers(List.of(standard)).initContainers(List.of(init));
		final var pod = createPodWithSpec("default", "pod", spec);

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void ephemeralContainer_privileged_detected() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var standard = createContainer("docker.io/nginx:latest");
		final var ephemeral = new V1EphemeralContainer()
				.name("debug")
				.image("docker.io/debug:latest")
				.securityContext(new V1SecurityContext().privileged(true));
		final var spec = new V1PodSpec().containers(List.of(standard))
				.ephemeralContainers(List.of(ephemeral));
		final var pod = createPodWithSpec("default", "pod", spec);

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
	}

	@Test
	public void standardAndInitContainers_bothEvaluated() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var standard = createContainerWithSecCtx("docker.io/nginx:latest",
				new V1SecurityContext().privileged(true));
		final var init = createContainerWithSecCtx("docker.io/init:latest",
				new V1SecurityContext().privileged(true));
		init.setName("init-container");
		final var spec = new V1PodSpec().containers(List.of(standard)).initContainers(List.of(init));
		final var pod = createPodWithSpec("default", "pod", spec);

		assertEquals(2, rule.evaluate(pod).size());
	}

	@Test
	public void containerType_filtering() {
		// Rule targeting only privileged init containers
		final var rule = createRule("priv-init",
				"container.containerType == 'init' && container.securityContext.privileged == true");
		final var standard = createContainerWithSecCtx("docker.io/nginx:latest",
				new V1SecurityContext().privileged(true));
		final var init = createContainerWithSecCtx("docker.io/init:latest",
				new V1SecurityContext().privileged(true));
		init.setName("init-container");
		final var spec = new V1PodSpec().containers(List.of(standard)).initContainers(List.of(init));
		final var pod = createPodWithSpec("default", "pod", spec);

		// Only the init container matches (standard is privileged but type != 'init')
		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void containerType_standard() {
		final var rule = createRule("type-check", "container.containerType == 'standard'");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void containerType_ephemeral() {
		final var rule = createRule("type-check", "container.containerType == 'ephemeral'");
		final var standard = createContainer("docker.io/nginx:latest");
		final var ephemeral = new V1EphemeralContainer()
				.name("debug")
				.image("docker.io/debug:latest");
		final var spec = new V1PodSpec().containers(List.of(standard))
				.ephemeralContainers(List.of(ephemeral));
		final var pod = createPodWithSpec("default", "pod", spec);

		// Only the ephemeral container matches
		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void nullInitContainers_noError() {
		final var rule = createRule("test", "true");
		final var container = createContainer("docker.io/nginx:latest");
		// Default pod has null initContainers
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void nullEphemeralContainers_noError() {
		final var rule = createRule("test", "true");
		final var container = createContainer("docker.io/nginx:latest");
		// Default pod has null ephemeralContainers
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void mixedContainerTypes_partialMatch() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var standardPriv = createContainerWithSecCtx("docker.io/nginx:latest",
				new V1SecurityContext().privileged(true));
		final var standardSafe = createContainerWithSecCtx("docker.io/redis:7.0",
				new V1SecurityContext().privileged(false));
		final var initPriv = createContainerWithSecCtx("docker.io/init:latest",
				new V1SecurityContext().privileged(true));
		initPriv.setName("init-container");
		final var spec = new V1PodSpec()
				.containers(List.of(standardPriv, standardSafe))
				.initContainers(List.of(initPriv));
		final var pod = createPodWithSpec("default", "pod", spec);

		// 1 standard privileged + 1 init privileged = 2 violations
		assertEquals(2, rule.evaluate(pod).size());
	}

	// ================================================================
	// Phase 5 — Severity tests
	// ================================================================

	@Test
	public void severityFieldParsed() {
		final var rule = createRuleWithSeverity("test", "true", "critical");
		assertEquals("critical", rule.getSeverity());
	}

	@Test
	public void severityFieldNull_whenAbsent() {
		final var rule = createRule("test", "true");
		assertNull(rule.getSeverity());
	}

	@Test
	public void severityInViolationLabels() {
		final var rule = createRuleWithSeverity("test", "true", "critical");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertEquals(1, violations.size());
		assertEquals("critical", violations.get(0).createLabels().get("severity"));
	}

	@Test
	public void severityOmittedFromLabels_whenNull() {
		final var rule = createRule("test", "true");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		final var violations = rule.evaluate(pod);
		assertFalse(violations.get(0).createLabels().containsKey("severity"));
	}

	@Test
	public void severityValues_allAccepted() {
		for (final var sev : List.of("critical", "high", "medium", "low", "info")) {
			final var rule = createRuleWithSeverity("test-" + sev, "true", sev);
			assertEquals(sev, rule.getSeverity());
		}
	}

	// ================================================================
	// Phase 6 — Expression pre-parsing tests
	// ================================================================

	@Test
	public void expressionCached_sameResult() {
		final var rule = createRule("cached",
				"container.securityContext.privileged == true");

		// First evaluation
		final var secCtx1 = new V1SecurityContext().privileged(true);
		final var c1 = createContainerWithSecCtx("docker.io/nginx:latest", secCtx1);
		final var pod1 = createPod("default", "pod1", List.of(c1));
		assertEquals(1, rule.evaluate(pod1).size());

		// Second evaluation with different context — cached expression should work
		final var secCtx2 = new V1SecurityContext().privileged(false);
		final var c2 = createContainerWithSecCtx("docker.io/redis:7.0", secCtx2);
		final var pod2 = createPod("default", "pod2", List.of(c2));
		assertTrue(rule.evaluate(pod2).isEmpty());
	}

	@Test
	public void invalidExpression_failsOnFirstUse() {
		final var rule = createRule("broken", "!!!invalid!!!");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		// Should return empty, not throw
		assertTrue(rule.evaluate(pod).isEmpty());
	}

	// ================================================================
	// Documented examples — every example from the "how complex" answer
	// ================================================================

	@Test
	public void example_numericLessThan() {
		final var rule = createRule("low-uid",
				"container.securityContext.runAsUser != null && container.securityContext.runAsUser < 1000");
		final var secCtx = new V1SecurityContext().runAsUser(500L);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_numericLessThan_noMatch() {
		final var rule = createRule("low-uid",
				"container.securityContext.runAsUser != null && container.securityContext.runAsUser < 1000");
		final var secCtx = new V1SecurityContext().runAsUser(65534L);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void example_tripleOrHostNamespaces() {
		final var rule = createRule("host-ns",
				"spec.hostNetwork == true || spec.hostPID == true || spec.hostIPC == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var spec = new V1PodSpec().containers(List.of(container))
				.hostNetwork(false).hostPID(false).hostIPC(true);
		final var pod = createPodWithSpec("default", "pod", spec);

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_tripleOrHostNamespaces_allFalse() {
		final var rule = createRule("host-ns",
				"spec.hostNetwork == true || spec.hostPID == true || spec.hostIPC == true");
		final var container = createContainer("docker.io/nginx:latest");
		final var spec = new V1PodSpec().containers(List.of(container))
				.hostNetwork(false).hostPID(false).hostIPC(false);
		final var pod = createPodWithSpec("default", "pod", spec);

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void example_elvisOperator() {
		final var rule = createRule("elvis",
				"(container.securityContext.runAsUser ?: -1) == 0");
		final var secCtx = new V1SecurityContext().runAsUser(0L);
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_elvisOperator_nullFallback() {
		// runAsUser is null -> Elvis returns -1 -> -1 == 0 is false
		final var rule = createRule("elvis",
				"(container.securityContext.runAsUser ?: -1) == 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void example_endsWith() {
		final var rule = createRule("sidecar", "container.name.endsWith('-sidecar')");
		final var container = new V1Container().name("envoy-sidecar").image("docker.io/envoy:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_endsWith_noMatch() {
		final var rule = createRule("sidecar", "container.name.endsWith('-sidecar')");
		final var container = new V1Container().name("main-app").image("docker.io/app:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void example_equalsIgnoreCase() {
		final var rule = createRule("sa-case",
				"spec.serviceAccountName.equalsIgnoreCase('admin')");
		final var container = createContainer("docker.io/nginx:latest");
		final var spec = new V1PodSpec().containers(List.of(container)).serviceAccountName("ADMIN");
		final var pod = createPodWithSpec("default", "pod", spec);

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_capabilitiesSizeGreaterThanZero() {
		final var rule = createRule("has-caps",
				"container.securityContext.capabilities.add.size() > 0");
		final var secCtx = new V1SecurityContext()
				.capabilities(new V1Capabilities().add(List.of("NET_ADMIN")));
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_capabilitiesSizeGreaterThanZero_empty() {
		final var rule = createRule("has-caps",
				"container.securityContext.capabilities.add.size() > 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void example_listGetIndex() {
		final var rule = createRule("first-cap",
				"{'NET_ADMIN','SYS_ADMIN','SYS_PTRACE'}.contains(container.securityContext.capabilities.add.get(0))");
		final var secCtx = new V1SecurityContext()
				.capabilities(new V1Capabilities().add(List.of("SYS_ADMIN", "NET_RAW")));
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_safeNavigation() {
		// tag is null (no tag in image) -> safe navigation returns null -> null == 'latest' is false
		final var rule = createRule("safe-nav",
				"container.image.tag?.toLowerCase() == 'latest'");
		final var container = createContainer("docker.io/nginx");
		final var pod = createPod("default", "pod", List.of(container));

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void example_safeNavigation_match() {
		final var rule = createRule("safe-nav",
				"container.image.tag?.toLowerCase() == 'latest'");
		final var container = createContainer("docker.io/nginx:LATEST");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_complexCompoundRule() {
		final var rule = createRule("complex",
				"container.securityContext.privileged == true" +
						" || container.securityContext.allowPrivilegeEscalation == true" +
						" || (container.securityContext.capabilities.add.size() > 0" +
						"     && !container.securityContext.capabilities.drop.contains('ALL'))" +
						" || spec.hostNetwork == true" +
						" || container.securityContext.runAsUser == 0");

		// Trigger via capabilities: has adds but no drop-ALL
		final var secCtx = new V1SecurityContext()
				.privileged(false)
				.allowPrivilegeEscalation(false)
				.capabilities(new V1Capabilities().add(List.of("NET_ADMIN")));
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var spec = new V1PodSpec().containers(List.of(container)).hostNetwork(false);
		final var pod = createPodWithSpec("default", "pod", spec);

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_complexCompoundRule_allSafe() {
		final var rule = createRule("complex",
				"container.securityContext.privileged == true" +
						" || container.securityContext.allowPrivilegeEscalation == true" +
						" || (container.securityContext.capabilities.add.size() > 0" +
						"     && !container.securityContext.capabilities.drop.contains('ALL'))" +
						" || spec.hostNetwork == true" +
						" || container.securityContext.runAsUser == 0");

		// All conditions are false
		final var secCtx = new V1SecurityContext()
				.privileged(false)
				.allowPrivilegeEscalation(false)
				.runAsUser(1000L)
				.capabilities(new V1Capabilities().drop(List.of("ALL")));
		final var container = createContainerWithSecCtx("docker.io/nginx:latest", secCtx);
		final var spec = new V1PodSpec().containers(List.of(container)).hostNetwork(false);
		final var pod = createPodWithSpec("default", "pod", spec);

		assertTrue(rule.evaluate(pod).isEmpty());
	}

	@Test
	public void example_labelsContainsKey_k8sStyle() {
		final var rule = createRule("managed-by",
				"metadata.labels.containsKey('app.kubernetes.io/managed-by')");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));
		pod.getMetadata().setLabels(Map.of("app.kubernetes.io/managed-by", "helm"));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_argsSize() {
		final var rule = createRule("no-args", "container.args.size() == 0");
		final var container = createContainer("docker.io/nginx:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_semverRegex() {
		final var rule = createRule("semver",
				"container.image.tag.matches('v[0-9]+\\.[0-9]+\\.[0-9]+')");
		final var container = createContainer("docker.io/app:v1.25.3");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

	@Test
	public void example_imageNameContainsDebug() {
		final var rule = createRule("debug-image", "container.image.name.contains('debug')");
		final var container = createContainer("docker.io/debug-tools:latest");
		final var pod = createPod("default", "pod", List.of(container));

		assertEquals(1, rule.evaluate(pod).size());
	}

}
