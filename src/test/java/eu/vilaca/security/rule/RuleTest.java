package eu.vilaca.security.rule;

import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.rule.model.Namespace;
import eu.vilaca.security.service.K8sContextBuilder;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.models.*;
import org.junit.Test;

import java.util.ArrayList;
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

	private static List<PodRuleViolation> evaluateK8s(Rule rule, V1Pod pod) {
		return K8sContextBuilder.evaluatePod(rule, pod);
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
		assertFalse(rule.allNamespaces());
	}

	// --- evaluate() with simple rules ---

	@Test
	public void evaluateAlwaysTrueRule() {
		final var rule = createRule("always-true", "true");
		final var pod = createPod("default", "nginx-pod", List.of(createContainer("docker.io/nginx:latest")));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void evaluateAlwaysFalseRule() {
		final var rule = createRule("always-false", "false");
		final var pod = createPod("default", "nginx-pod", List.of(createContainer("docker.io/nginx:latest")));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void evaluatePodWithNullSpec() {
		final var rule = createRule("test", "true");
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace("default").name("broken-pod"));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void evaluatePodWithNullContainers() {
		final var rule = createRule("test", "true");
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace("default").name("empty-pod"));
		pod.setSpec(new V1PodSpec());
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void evaluateMultipleContainers_allMatch() {
		final var rule = createRule("always-true", "true");
		final var pod = createPod("default", "multi-pod",
				List.of(createContainer("docker.io/nginx:latest"), createContainer("docker.io/redis:7.0")));
		assertEquals(2, evaluateK8s(rule, pod).size());
	}

	@Test
	public void evaluateMultipleContainers_noneMatch() {
		final var rule = createRule("always-false", "false");
		final var pod = createPod("default", "multi-pod",
				List.of(createContainer("docker.io/nginx:latest"), createContainer("docker.io/redis:7.0")));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void evaluateEmptyContainersList() {
		final var rule = createRule("test", "true");
		final var pod = createPod("default", "empty-pod", Collections.emptyList());
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	// --- Security context rules ---

	@Test
	public void runAsRootDetection_podLevel() {
		final var rule = createRule("run-as-root", "securityContext.runAsUser == 0");
		final var pod = createPod("default", "root-pod",
				List.of(createContainer("docker.io/nginx:latest")),
				new V1PodSecurityContext().runAsUser(0L), null);
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void runAsRootDetection_containerLevel() {
		final var rule = createRule("run-as-root", "container.securityContext.runAsUser == 0");
		final var pod = createPod("default", "root-container",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().runAsUser(0L))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void runAsNonRoot_noViolation() {
		final var rule = createRule("run-as-root", "securityContext.runAsUser == 0");
		final var pod = createPod("default", "safe-pod",
				List.of(createContainer("docker.io/nginx:latest")),
				new V1PodSecurityContext().runAsUser(1000L), null);
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void privilegedContainerDetection() {
		final var rule = createRule("privileged", "container.securityContext.privileged == true");
		final var pod = createPod("default", "priv-pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void nonPrivilegedContainer_noViolation() {
		final var rule = createRule("privileged", "container.securityContext.privileged == true");
		final var pod = createPod("default", "safe-pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(false))));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void allowPrivilegeEscalation() {
		final var rule = createRule("priv-escalation", "container.securityContext.allowPrivilegeEscalation == true");
		final var pod = createPod("default", "escalation-pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().allowPrivilegeEscalation(true))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void readOnlyRootFilesystem_false() {
		final var rule = createRule("readonly-fs", "container.securityContext.readOnlyRootFilesystem == false");
		final var pod = createPod("default", "rw-pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().readOnlyRootFilesystem(false))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void readOnlyRootFilesystem_true_noViolation() {
		final var rule = createRule("readonly-fs", "container.securityContext.readOnlyRootFilesystem == false");
		final var pod = createPod("default", "ro-pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().readOnlyRootFilesystem(true))));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	// --- hostPID ---

	@Test
	public void hostPIDEnabled() {
		final var rule = createRule("hostpid", "spec.hostPID == true");
		final var pod = createPod("default", "hostpid-pod",
				List.of(createContainer("docker.io/nginx:latest")), null, true);
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void hostPIDDisabled() {
		final var rule = createRule("hostpid", "spec.hostPID == true");
		final var pod = createPod("default", "safe-pod",
				List.of(createContainer("docker.io/nginx:latest")), null, false);
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	// --- Image registry rules ---

	@Test
	public void registryCheckMatch() {
		final var rule = createRule("registry-check", "container.image.registry != 'registry.k8s.io'");
		final var pod = createPod("default", "nginx-pod", List.of(createContainer("docker.io/nginx:latest")));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void registryCheckNoMatch() {
		final var rule = createRule("registry-check", "container.image.registry != 'registry.k8s.io'");
		final var pod = createPod("default", "kube-proxy", List.of(createContainer("registry.k8s.io/kube-proxy:v1.28")));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	// --- Compound rules ---

	@Test
	public void compoundOrRule_firstTrue() {
		final var rule = createRule("compound-or", "securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0");
		final var pod = createPod("default", "root-pod",
				List.of(createContainer("docker.io/nginx:latest")),
				new V1PodSecurityContext().runAsUser(0L), null);
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void compoundOrRule_secondTrue() {
		final var rule = createRule("compound-or", "securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0");
		final var pod = createPod("default", "root-container",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().runAsUser(0L))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void compoundAndRule_bothTrue() {
		final var rule = createRule("compound-and", "container.securityContext.privileged == true && container.securityContext.allowPrivilegeEscalation == true");
		final var pod = createPod("default", "bad-pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true).allowPrivilegeEscalation(true))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void compoundAndRule_onlyOneTrue() {
		final var rule = createRule("compound-and", "container.securityContext.privileged == true && container.securityContext.allowPrivilegeEscalation == true");
		final var pod = createPod("default", "half-bad-pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true).allowPrivilegeEscalation(false))));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	// --- Invalid SpEL ---

	@Test
	public void invalidSpelExpression_returnsEmpty() {
		final var rule = createRule("broken", "this is not valid SpEL !!!@#$");
		final var pod = createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void spelReferencingNonExistentProperty_returnsEmpty() {
		final var rule = createRule("bad-prop", "container.nonExistent == true");
		final var pod = createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	// --- Null security contexts ---

	@Test
	public void nullPodSecurityContext_ruleAccessingIt() {
		final var rule = createRule("null-sec-ctx", "securityContext.runAsUser == 0");
		final var pod = createPod("default", "no-sec-pod", List.of(createContainer("docker.io/nginx:latest")));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void nullContainerSecurityContext_defaultValues() {
		final var rule = createRule("no-container-sec", "container.securityContext.privileged == true");
		final var pod = createPod("default", "no-sec-container", List.of(createContainer("docker.io/nginx:latest")));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void disabledRuleState() {
		final var rule = createRule("disabled", "true");
		rule.setEnabled(false);
		assertFalse(rule.isEnabled());
	}

	@Test
	public void violationContainsCorrectData() {
		final var rule = createRule("test-rule", "true");
		rule.setAlert("my-alert");
		final var pod = createPod("prod", "web-server", List.of(createContainer("docker.io/nginx:1.25")));
		final var violations = evaluateK8s(rule, pod);
		assertEquals(1, violations.size());
		assertEquals("test-rule", violations.get(0).getRule().getName());
		assertEquals("my-alert", violations.get(0).getRule().getAlert());
		assertEquals("prod", violations.get(0).getNamespace());
		assertEquals("web-server", violations.get(0).getPod());
	}

	@Test
	public void podWithNullMetadata() {
		final var rule = createRule("test", "true");
		final var pod = new V1Pod();
		pod.setSpec(new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))));
		final var violations = evaluateK8s(rule, pod);
		if (!violations.isEmpty()) {
			assertNull(violations.get(0).getNamespace());
			assertNull(violations.get(0).getPod());
		}
	}

	@Test
	public void mixedContainers_onlyMatchingOnesViolate() {
		final var rule = createRule("privileged-check", "container.securityContext.privileged == true");
		final var pod = createPod("default", "mixed-pod", List.of(
				createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true)),
				createContainerWithSecCtx("docker.io/redis:7.0", new V1SecurityContext().privileged(false))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	// --- Null safety ---

	@Test
	public void nullPodSecurityContext_compoundOr_rightSideMatches() {
		final var rule = createRule("compound-or", "securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0");
		final var pod = createPod("default", "root-container",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().runAsUser(0L))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void nullPodSecurityContext_compoundOr_neitherMatches() {
		final var rule = createRule("compound-or", "securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0");
		final var pod = createPod("default", "safe-container",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().runAsUser(1000L))));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void nullPodSecurityContext_compoundAnd_safeEvaluation() {
		final var rule = createRule("compound-and", "securityContext.runAsNonRoot == true && container.securityContext.privileged == true");
		final var pod = createPod("default", "pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true))));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void allContextSubObjectsAlwaysInitialized() {
		final var rule = createRule("deep-access", "securityContext.runAsUser == null && container.securityContext.privileged == null && spec.hostPID == null");
		final var pod = createPod("default", "bare-pod", List.of(createContainer("docker.io/nginx:latest")));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	// --- Instance methods ---

	@Test
	public void spelStringStartsWith() {
		final var rule = createRule("starts-with", "container.image.registry.startsWith('docker')");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).size());
	}

	@Test
	public void spelStringStartsWith_noMatch() {
		final var rule = createRule("starts-with", "container.image.registry.startsWith('docker')");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("ghcr.io/org/app:v1")))).isEmpty());
	}

	@Test
	public void spelStringContains() {
		final var rule = createRule("contains", "container.image.name.contains('ngi')");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).size());
	}

	@Test
	public void spelStringContains_noMatch() {
		final var rule = createRule("contains", "container.image.name.contains('ngi')");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/redis:7.0")))).isEmpty());
	}

	@Test
	public void spelStringToLowerCase() {
		final var rule = createRule("lower", "container.image.tag.toLowerCase() == 'latest'");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:LATEST")))).size());
	}

	@Test
	public void spelStringMatches_regex() {
		final var rule = createRule("regex", "container.image.tag.matches('v[0-9]+\\.[0-9]+')");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/app:v1.25")))).size());
	}

	@Test
	public void spelStringMatches_regex_noMatch() {
		final var rule = createRule("regex", "container.image.tag.matches('v[0-9]+\\.[0-9]+')");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/app:latest")))).isEmpty());
	}

	@Test
	public void spelInlineListContains_allowlist() {
		final var rule = createRule("allowlist", "!{'registry.k8s.io', 'docker.io', 'ghcr.io'}.contains(container.image.registry)");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("quay.io/prometheus/node-exporter:v1")))).size());
	}

	@Test
	public void spelInlineListContains_allowlist_noViolation() {
		final var rule = createRule("allowlist", "!{'registry.k8s.io', 'docker.io', 'ghcr.io'}.contains(container.image.registry)");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).isEmpty());
	}

	@Test
	public void spelStringLength() {
		final var rule = createRule("long-tag", "container.image.tag.length() > 10");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/app:this-is-a-very-long-tag")))).size());
	}

	// --- Expanded Context schema ---

	@Test
	public void hostNetworkEnabled_detected() {
		final var rule = createRule("hostnet", "spec.hostNetwork == true");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).hostNetwork(true);
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void hostNetworkDisabled_noViolation() {
		final var rule = createRule("hostnet", "spec.hostNetwork == true");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).hostNetwork(false);
		assertTrue(evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).isEmpty());
	}

	@Test
	public void hostIPCEnabled_detected() {
		final var rule = createRule("hostipc", "spec.hostIPC == true");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).hostIPC(true);
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void serviceAccountName_match() {
		final var rule = createRule("sa-check", "spec.serviceAccountName == 'cluster-admin'");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).serviceAccountName("cluster-admin");
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void automountServiceAccountToken_true() {
		final var rule = createRule("automount", "spec.automountServiceAccountToken != false");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).automountServiceAccountToken(true);
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void capabilitiesDropAll_detected() {
		final var rule = createRule("drop-all", "!container.securityContext.capabilities.drop.contains('ALL')");
		final var pod = createPod("default", "pod", List.of(
				createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().capabilities(new V1Capabilities().drop(List.of("NET_RAW"))))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void capabilitiesDropAll_noViolation() {
		final var rule = createRule("drop-all", "!container.securityContext.capabilities.drop.contains('ALL')");
		final var pod = createPod("default", "pod", List.of(
				createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().capabilities(new V1Capabilities().drop(List.of("ALL"))))));
		assertTrue(evaluateK8s(rule, pod).isEmpty());
	}

	@Test
	public void capabilitiesAddNetAdmin_detected() {
		final var rule = createRule("net-admin", "container.securityContext.capabilities.add.contains('NET_ADMIN')");
		final var pod = createPod("default", "pod", List.of(
				createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().capabilities(new V1Capabilities().add(List.of("NET_ADMIN", "SYS_TIME"))))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void capabilitiesEmpty_noViolation() {
		final var rule = createRule("net-admin", "container.securityContext.capabilities.add.contains('NET_ADMIN')");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).isEmpty());
	}

	@Test
	public void seccompProfileType_unconfined() {
		final var rule = createRule("seccomp", "container.securityContext.seccompProfileType == 'Unconfined'");
		final var pod = createPod("default", "pod", List.of(
				createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().seccompProfile(new V1SeccompProfile().type("Unconfined")))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void containerName_access() {
		final var rule = createRule("name-check", "container.name == 'sidecar'");
		final var pod = createPod("default", "pod", List.of(new V1Container().name("sidecar").image("docker.io/envoy:latest")));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void containerCommand_access() {
		final var rule = createRule("cmd-check", "container.command.contains('/bin/sh')");
		final var pod = createPod("default", "pod", List.of(
				new V1Container().name("c").image("docker.io/alpine:latest").command(List.of("/bin/sh", "-c", "echo hello"))));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void podLabels_access() {
		final var rule = createRule("label-check", "metadata.labels.containsKey('app')");
		final var pod = createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")));
		pod.getMetadata().setLabels(Map.of("app", "web", "env", "prod"));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void podAnnotations_access() {
		final var rule = createRule("annotation-check", "metadata.annotations.containsKey('iam.amazonaws.com/role')");
		final var pod = createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")));
		pod.getMetadata().setAnnotations(Map.of("iam.amazonaws.com/role", "admin"));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void podMetadata_namespace() {
		final var rule = createRule("ns-check", "metadata.namespace == 'kube-system'");
		assertEquals(1, evaluateK8s(rule, createPod("kube-system", "pod", List.of(createContainer("docker.io/nginx:latest")))).size());
	}

	@Test
	public void emptyCollections_neverNull() {
		final var rule = createRule("empty-check",
				"container.securityContext.capabilities.add.size() == 0 " +
						"&& container.securityContext.capabilities.drop.size() == 0 " +
						"&& container.command.size() == 0 " +
						"&& container.args.size() == 0 " +
						"&& container.ports.size() == 0 " +
						"&& metadata.labels.size() == 0 " +
						"&& metadata.annotations.size() == 0");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).size());
	}

	// --- Init & ephemeral containers ---

	@Test
	public void initContainer_privileged_detected() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var init = createContainerWithSecCtx("docker.io/init:latest", new V1SecurityContext().privileged(true));
		init.setName("init-container");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).initContainers(List.of(init));
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void initContainer_safe_noViolation() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var init = createContainerWithSecCtx("docker.io/init:latest", new V1SecurityContext().privileged(false));
		init.setName("init-container");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).initContainers(List.of(init));
		assertTrue(evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).isEmpty());
	}

	@Test
	public void ephemeralContainer_privileged_detected() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var ephemeral = new V1EphemeralContainer().name("debug").image("docker.io/debug:latest")
				.securityContext(new V1SecurityContext().privileged(true));
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).ephemeralContainers(List.of(ephemeral));
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void standardAndInitContainers_bothEvaluated() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var init = createContainerWithSecCtx("docker.io/init:latest", new V1SecurityContext().privileged(true));
		init.setName("init-container");
		final var spec = new V1PodSpec()
				.containers(List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true))))
				.initContainers(List.of(init));
		assertEquals(2, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void containerType_filtering() {
		final var rule = createRule("priv-init", "container.containerType == 'init' && container.securityContext.privileged == true");
		final var init = createContainerWithSecCtx("docker.io/init:latest", new V1SecurityContext().privileged(true));
		init.setName("init-container");
		final var spec = new V1PodSpec()
				.containers(List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true))))
				.initContainers(List.of(init));
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void containerType_standard() {
		final var rule = createRule("type-check", "container.containerType == 'standard'");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).size());
	}

	@Test
	public void containerType_ephemeral() {
		final var rule = createRule("type-check", "container.containerType == 'ephemeral'");
		final var ephemeral = new V1EphemeralContainer().name("debug").image("docker.io/debug:latest");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).ephemeralContainers(List.of(ephemeral));
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void nullInitContainers_noError() {
		final var rule = createRule("test", "true");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).size());
	}

	@Test
	public void nullEphemeralContainers_noError() {
		final var rule = createRule("test", "true");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).size());
	}

	@Test
	public void mixedContainerTypes_partialMatch() {
		final var rule = createRule("priv", "container.securityContext.privileged == true");
		final var initPriv = createContainerWithSecCtx("docker.io/init:latest", new V1SecurityContext().privileged(true));
		initPriv.setName("init-container");
		final var spec = new V1PodSpec()
				.containers(List.of(
						createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true)),
						createContainerWithSecCtx("docker.io/redis:7.0", new V1SecurityContext().privileged(false))))
				.initContainers(List.of(initPriv));
		assertEquals(2, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	// --- Severity ---

	@Test
	public void severityFieldParsed() {
		assertEquals("critical", createRuleWithSeverity("test", "true", "critical").getSeverity());
	}

	@Test
	public void severityFieldNull_whenAbsent() {
		assertNull(createRule("test", "true").getSeverity());
	}

	@Test
	public void severityInViolationLabels() {
		final var rule = createRuleWithSeverity("test", "true", "critical");
		final var violations = evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest"))));
		assertEquals("critical", violations.get(0).createLabels().get("severity"));
	}

	@Test
	public void severityOmittedFromLabels_whenNull() {
		final var rule = createRule("test", "true");
		final var violations = evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest"))));
		assertFalse(violations.get(0).createLabels().containsKey("severity"));
	}

	@Test
	public void severityValues_allAccepted() {
		for (final var sev : List.of("critical", "high", "medium", "low", "info")) {
			assertEquals(sev, createRuleWithSeverity("test-" + sev, "true", sev).getSeverity());
		}
	}

	// --- Expression pre-parsing ---

	@Test
	public void expressionCached_sameResult() {
		final var rule = createRule("cached", "container.securityContext.privileged == true");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod1",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().privileged(true))))).size());
		assertTrue(evaluateK8s(rule, createPod("default", "pod2",
				List.of(createContainerWithSecCtx("docker.io/redis:7.0", new V1SecurityContext().privileged(false))))).isEmpty());
	}

	@Test
	public void invalidExpression_failsOnFirstUse() {
		final var rule = createRule("broken", "!!!invalid!!!");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).isEmpty());
	}

	// --- Documented examples ---

	@Test
	public void example_numericLessThan() {
		final var rule = createRule("low-uid", "container.securityContext.runAsUser != null && container.securityContext.runAsUser < 1000");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().runAsUser(500L))))).size());
	}

	@Test
	public void example_numericLessThan_noMatch() {
		final var rule = createRule("low-uid", "container.securityContext.runAsUser != null && container.securityContext.runAsUser < 1000");
		assertTrue(evaluateK8s(rule, createPod("default", "pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().runAsUser(65534L))))).isEmpty());
	}

	@Test
	public void example_tripleOrHostNamespaces() {
		final var rule = createRule("host-ns", "spec.hostNetwork == true || spec.hostPID == true || spec.hostIPC == true");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).hostNetwork(false).hostPID(false).hostIPC(true);
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void example_tripleOrHostNamespaces_allFalse() {
		final var rule = createRule("host-ns", "spec.hostNetwork == true || spec.hostPID == true || spec.hostIPC == true");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).hostNetwork(false).hostPID(false).hostIPC(false);
		assertTrue(evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).isEmpty());
	}

	@Test
	public void example_elvisOperator() {
		final var rule = createRule("elvis", "(container.securityContext.runAsUser ?: -1) == 0");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest", new V1SecurityContext().runAsUser(0L))))).size());
	}

	@Test
	public void example_elvisOperator_nullFallback() {
		final var rule = createRule("elvis", "(container.securityContext.runAsUser ?: -1) == 0");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).isEmpty());
	}

	@Test
	public void example_endsWith() {
		final var rule = createRule("sidecar", "container.name.endsWith('-sidecar')");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod",
				List.of(new V1Container().name("envoy-sidecar").image("docker.io/envoy:latest")))).size());
	}

	@Test
	public void example_endsWith_noMatch() {
		final var rule = createRule("sidecar", "container.name.endsWith('-sidecar')");
		assertTrue(evaluateK8s(rule, createPod("default", "pod",
				List.of(new V1Container().name("main-app").image("docker.io/app:latest")))).isEmpty());
	}

	@Test
	public void example_equalsIgnoreCase() {
		final var rule = createRule("sa-case", "spec.serviceAccountName.equalsIgnoreCase('admin')");
		final var spec = new V1PodSpec().containers(List.of(createContainer("docker.io/nginx:latest"))).serviceAccountName("ADMIN");
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void example_capabilitiesSizeGreaterThanZero() {
		final var rule = createRule("has-caps", "container.securityContext.capabilities.add.size() > 0");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest",
						new V1SecurityContext().capabilities(new V1Capabilities().add(List.of("NET_ADMIN"))))))).size());
	}

	@Test
	public void example_capabilitiesSizeGreaterThanZero_empty() {
		final var rule = createRule("has-caps", "container.securityContext.capabilities.add.size() > 0");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).isEmpty());
	}

	@Test
	public void example_listGetIndex() {
		final var rule = createRule("first-cap", "{'NET_ADMIN','SYS_ADMIN','SYS_PTRACE'}.contains(container.securityContext.capabilities.add.get(0))");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod",
				List.of(createContainerWithSecCtx("docker.io/nginx:latest",
						new V1SecurityContext().capabilities(new V1Capabilities().add(List.of("SYS_ADMIN", "NET_RAW"))))))).size());
	}

	@Test
	public void example_safeNavigation() {
		final var rule = createRule("safe-nav", "container.image.tag?.toLowerCase() == 'latest'");
		assertTrue(evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx")))).isEmpty());
	}

	@Test
	public void example_safeNavigation_match() {
		final var rule = createRule("safe-nav", "container.image.tag?.toLowerCase() == 'latest'");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:LATEST")))).size());
	}

	@Test
	public void example_complexCompoundRule() {
		final var rule = createRule("complex",
				"container.securityContext.privileged == true || container.securityContext.allowPrivilegeEscalation == true || (container.securityContext.capabilities.add.size() > 0 && !container.securityContext.capabilities.drop.contains('ALL')) || spec.hostNetwork == true || container.securityContext.runAsUser == 0");
		final var spec = new V1PodSpec().containers(List.of(
				createContainerWithSecCtx("docker.io/nginx:latest",
						new V1SecurityContext().privileged(false).allowPrivilegeEscalation(false).capabilities(new V1Capabilities().add(List.of("NET_ADMIN")))))).hostNetwork(false);
		assertEquals(1, evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).size());
	}

	@Test
	public void example_complexCompoundRule_allSafe() {
		final var rule = createRule("complex",
				"container.securityContext.privileged == true || container.securityContext.allowPrivilegeEscalation == true || (container.securityContext.capabilities.add.size() > 0 && !container.securityContext.capabilities.drop.contains('ALL')) || spec.hostNetwork == true || container.securityContext.runAsUser == 0");
		final var spec = new V1PodSpec().containers(List.of(
				createContainerWithSecCtx("docker.io/nginx:latest",
						new V1SecurityContext().privileged(false).allowPrivilegeEscalation(false).runAsUser(1000L).capabilities(new V1Capabilities().drop(List.of("ALL")))))).hostNetwork(false);
		assertTrue(evaluateK8s(rule, createPodWithSpec("default", "pod", spec)).isEmpty());
	}

	@Test
	public void example_labelsContainsKey_k8sStyle() {
		final var rule = createRule("managed-by", "metadata.labels.containsKey('app.kubernetes.io/managed-by')");
		final var pod = createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")));
		pod.getMetadata().setLabels(Map.of("app.kubernetes.io/managed-by", "helm"));
		assertEquals(1, evaluateK8s(rule, pod).size());
	}

	@Test
	public void example_argsSize() {
		final var rule = createRule("no-args", "container.args.size() == 0");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/nginx:latest")))).size());
	}

	@Test
	public void example_semverRegex() {
		final var rule = createRule("semver", "container.image.tag.matches('v[0-9]+\\.[0-9]+\\.[0-9]+')");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/app:v1.25.3")))).size());
	}

	@Test
	public void example_imageNameContainsDebug() {
		final var rule = createRule("debug-image", "container.image.name.contains('debug')");
		assertEquals(1, evaluateK8s(rule, createPod("default", "pod", List.of(createContainer("docker.io/debug-tools:latest")))).size());
	}
}
