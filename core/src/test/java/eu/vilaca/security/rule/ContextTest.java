package eu.vilaca.security.rule;

import eu.vilaca.security.violation.ImageData;
import org.junit.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Tests the Context class and its nested classes, including SpEL evaluation
 * against Context objects (which is how rules work at runtime).
 */
public class ContextTest {

	private final SpelExpressionParser parser = new SpelExpressionParser();

	/**
	 * Evaluate using the same context configuration as Rule.evaluateRule() —
	 * forReadOnlyDataBinding + withInstanceMethods.
	 */
	private Object evaluate(Context ctx, String expression) {
		final var evalCtx = SimpleEvaluationContext
				.forReadOnlyDataBinding()
				.withInstanceMethods()
				.withRootObject(ctx)
				.build();
		return parser.parseExpression(expression).getValue(evalCtx);
	}

	private Context createMinimalContext(String image) {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData(image);
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.capabilities = new Context.Capabilities();
		ctx.spec = new Context.Spec();
		ctx.securityContext = new Context.PodSecurityContext();
		ctx.metadata = new Context.Metadata();
		return ctx;
	}

	// --- Container image access ---

	@Test
	public void spelCanAccessImageRegistry() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		assertEquals("docker.io", evaluate(ctx, "container.image.registry"));
	}

	@Test
	public void spelCanAccessImageName() {
		final var ctx = createMinimalContext("ghcr.io/org/myapp:v1");
		assertEquals("myapp", evaluate(ctx, "container.image.name"));
	}

	@Test
	public void spelCanAccessImageTag() {
		final var ctx = createMinimalContext("docker.io/nginx:1.25");
		assertEquals("1.25", evaluate(ctx, "container.image.tag"));
	}

	// --- Container security context ---

	@Test
	public void spelCanAccessPrivileged() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.privileged = true;
		assertEquals(true, evaluate(ctx, "container.securityContext.privileged == true"));
	}

	@Test
	public void spelPrivilegedFalse() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.privileged = false;
		assertEquals(false, evaluate(ctx, "container.securityContext.privileged == true"));
	}

	@Test
	public void spelCanAccessAllowPrivilegeEscalation() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.allowPrivilegeEscalation = true;
		assertEquals(true, evaluate(ctx, "container.securityContext.allowPrivilegeEscalation == true"));
	}

	@Test
	public void spelCanAccessReadOnlyRootFilesystem() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.readOnlyRootFilesystem = false;
		assertEquals(true, evaluate(ctx, "container.securityContext.readOnlyRootFilesystem == false"));
	}

	@Test
	public void spelCanAccessContainerRunAsUser() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.runAsUser = 0L;
		assertEquals(true, evaluate(ctx, "container.securityContext.runAsUser == 0"));
	}

	// --- Pod security context ---

	@Test
	public void spelCanAccessPodRunAsUser() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.securityContext.runAsUser = 0L;
		assertEquals(true, evaluate(ctx, "securityContext.runAsUser == 0"));
	}

	@Test
	public void spelCanAccessPodRunAsGroup() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.securityContext.runAsGroup = 1000L;
		assertEquals(1000L, evaluate(ctx, "securityContext.runAsGroup"));
	}

	@Test
	public void spelCanAccessPodRunAsNonRoot() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.securityContext.runAsNonRoot = true;
		assertEquals(true, evaluate(ctx, "securityContext.runAsNonRoot"));
	}

	// --- Spec ---

	@Test
	public void spelCanAccessHostPID() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.spec.hostPID = true;
		assertEquals(true, evaluate(ctx, "spec.hostPID == true"));
	}

	@Test
	public void spelHostPIDFalse() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.spec.hostPID = false;
		assertEquals(false, evaluate(ctx, "spec.hostPID == true"));
	}

	// --- Null fields ---

	@Test
	public void spelNullSecurityContext() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.capabilities = new Context.Capabilities();
		// ctx.securityContext is null — this tests raw SpEL behavior

		try {
			evaluate(ctx, "securityContext.runAsUser == 0");
			fail("Expected exception for null securityContext");
		} catch (Exception e) {
			// Expected — accessing property on null throws
		}
	}

	@Test
	public void spelNullPrivilegedField() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		// privileged is null
		assertEquals(false, evaluate(ctx, "container.securityContext.privileged == true"));
	}

	// --- Compound expressions ---

	@Test
	public void compoundOrExpression() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.privileged = true;
		ctx.container.securityContext.allowPrivilegeEscalation = false;

		assertEquals(true, evaluate(ctx,
				"container.securityContext.privileged == true || container.securityContext.allowPrivilegeEscalation == true"));
	}

	@Test
	public void compoundAndExpression() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.privileged = true;
		ctx.container.securityContext.allowPrivilegeEscalation = true;

		assertEquals(true, evaluate(ctx,
				"container.securityContext.privileged == true && container.securityContext.allowPrivilegeEscalation == true"));
	}

	@Test
	public void registryComparisonExpression() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		assertEquals(true, evaluate(ctx,
				"container.image.registry != 'registry.k8s.io'"));
	}

	@Test
	public void multiRegistryCompoundExpression() {
		final var ctx = createMinimalContext("quay.io/prometheus/node-exporter");
		assertEquals(true, evaluate(ctx,
				"container.image.registry != 'registry.k8s.io' " +
						"&& container.image.registry != 'docker.io' " +
						"&& container.image.registry != 'ghcr.io'"));
	}

	@Test
	public void multiRegistryCompoundExpression_matchesOneRegistry() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		assertEquals(false, evaluate(ctx,
				"container.image.registry != 'registry.k8s.io' " +
						"&& container.image.registry != 'docker.io' " +
						"&& container.image.registry != 'ghcr.io'"));
	}

	// ================================================================
	// Phase 2 — Instance method tests
	// ================================================================

	@Test
	public void spelMethodCall_startsWith() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		assertEquals(true, evaluate(ctx, "container.image.registry.startsWith('docker')"));
	}

	@Test
	public void spelMethodCall_contains() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		assertEquals(true, evaluate(ctx, "container.image.name.contains('ngi')"));
	}

	@Test
	public void spelMethodCall_matches_regex() {
		final var ctx = createMinimalContext("docker.io/app:v1.25");
		assertEquals(true, evaluate(ctx, "container.image.tag.matches('v\\d+\\.\\d+')"));
	}

	@Test
	public void spelMethodCall_matches_regex_noMatch() {
		final var ctx = createMinimalContext("docker.io/app:latest");
		assertEquals(false, evaluate(ctx, "container.image.tag.matches('v\\d+\\.\\d+')"));
	}

	@Test
	public void spelInlineList_contains() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		assertEquals(true, evaluate(ctx,
				"{'docker.io', 'ghcr.io'}.contains(container.image.registry)"));
	}

	@Test
	public void spelInlineList_contains_noMatch() {
		final var ctx = createMinimalContext("quay.io/app:latest");
		assertEquals(false, evaluate(ctx,
				"{'docker.io', 'ghcr.io'}.contains(container.image.registry)"));
	}

	@Test
	public void spelMethodCall_onNullString() {
		// Tag is null for images without tags
		final var ctx = createMinimalContext("docker.io/nginx");
		try {
			evaluate(ctx, "container.image.tag.startsWith('v')");
			fail("Expected exception for null string method call");
		} catch (Exception e) {
			// Expected: calling method on null throws
		}
	}

	@Test
	public void spelMethodCall_toLowerCase() {
		final var ctx = createMinimalContext("docker.io/nginx:LATEST");
		assertEquals(true, evaluate(ctx, "container.image.tag.toLowerCase() == 'latest'"));
	}

	@Test
	public void spelMethodCall_length() {
		final var ctx = createMinimalContext("docker.io/nginx:v1.2.3");
		assertEquals(true, evaluate(ctx, "container.image.tag.length() > 3"));
	}

	// ================================================================
	// Phase 3 — Expanded Context schema tests
	// ================================================================

	@Test
	public void spelCanAccessHostNetwork() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.spec.hostNetwork = true;
		assertEquals(true, evaluate(ctx, "spec.hostNetwork == true"));
	}

	@Test
	public void spelCanAccessHostIPC() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.spec.hostIPC = true;
		assertEquals(true, evaluate(ctx, "spec.hostIPC == true"));
	}

	@Test
	public void spelCanAccessServiceAccountName() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.spec.serviceAccountName = "cluster-admin";
		assertEquals("cluster-admin", evaluate(ctx, "spec.serviceAccountName"));
	}

	@Test
	public void spelCanAccessAutomountServiceAccountToken() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.spec.automountServiceAccountToken = true;
		assertEquals(true, evaluate(ctx, "spec.automountServiceAccountToken == true"));
	}

	@Test
	public void spelCanAccessCapabilitiesDrop() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.capabilities.drop = List.of("ALL");
		assertEquals(true, evaluate(ctx,
				"container.securityContext.capabilities.drop.contains('ALL')"));
	}

	@Test
	public void spelCanAccessCapabilitiesAdd() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.capabilities.add = List.of("NET_ADMIN", "SYS_TIME");
		assertEquals(true, evaluate(ctx,
				"container.securityContext.capabilities.add.contains('NET_ADMIN')"));
	}

	@Test
	public void spelCapabilitiesEmpty_safeAccess() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		// capabilities.add/drop are empty by default
		assertEquals(false, evaluate(ctx,
				"container.securityContext.capabilities.add.contains('NET_ADMIN')"));
		assertEquals(0, evaluate(ctx,
				"container.securityContext.capabilities.drop.size()"));
	}

	@Test
	public void spelCanAccessContainerName() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.name = "sidecar";
		assertEquals("sidecar", evaluate(ctx, "container.name"));
	}

	@Test
	public void spelCanAccessContainerCommand() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.command = List.of("/bin/sh", "-c", "echo hello");
		assertEquals(true, evaluate(ctx, "container.command.contains('/bin/sh')"));
	}

	@Test
	public void spelCanAccessContainerArgs() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.args = List.of("--verbose", "--port=8080");
		assertEquals(true, evaluate(ctx, "container.args.contains('--verbose')"));
	}

	@Test
	public void spelCanAccessContainerPorts() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.ports = List.of(80, 443);
		assertEquals(true, evaluate(ctx, "container.ports.contains(80)"));
	}

	@Test
	public void spelCanAccessContainerType() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.containerType = "init";
		assertEquals(true, evaluate(ctx, "container.containerType == 'init'"));
	}

	@Test
	public void spelCanAccessMetadataLabels() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.metadata.labels = Map.of("app", "web", "env", "prod");
		assertEquals(true, evaluate(ctx, "metadata.labels.containsKey('app')"));
	}

	@Test
	public void spelCanAccessMetadataAnnotations() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.metadata.annotations = Map.of("key", "value");
		assertEquals(true, evaluate(ctx, "metadata.annotations.containsKey('key')"));
	}

	@Test
	public void spelCanAccessMetadataName() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.metadata.name = "my-pod";
		assertEquals("my-pod", evaluate(ctx, "metadata.name"));
	}

	@Test
	public void spelCanAccessMetadataNamespace() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.metadata.namespace = "kube-system";
		assertEquals("kube-system", evaluate(ctx, "metadata.namespace"));
	}

	@Test
	public void spelCanAccessSeccompProfileType() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.seccompProfileType = "RuntimeDefault";
		assertEquals("RuntimeDefault", evaluate(ctx,
				"container.securityContext.seccompProfileType"));
	}

	@Test
	public void spelCanAccessProcMount() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.container.securityContext.procMount = "Unmasked";
		assertEquals(true, evaluate(ctx,
				"container.securityContext.procMount == 'Unmasked'"));
	}

	@Test
	public void spelCanAccessFsGroup() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.securityContext.fsGroup = 1000L;
		assertEquals(1000L, evaluate(ctx, "securityContext.fsGroup"));
	}

	@Test
	public void spelCanAccessSupplementalGroups() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.securityContext.supplementalGroups = List.of(1000L, 2000L);
		assertEquals(true, evaluate(ctx,
				"securityContext.supplementalGroups.contains(1000L)"));
	}

	@Test
	public void spelCanAccessPodSeccompProfileType() {
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		ctx.securityContext.seccompProfileType = "Localhost";
		assertEquals("Localhost", evaluate(ctx, "securityContext.seccompProfileType"));
	}

	@Test
	public void spelEmptyCollections_safeAccess() {
		// All collection fields should default to empty, not null
		final var ctx = createMinimalContext("docker.io/nginx:latest");
		assertEquals(0, evaluate(ctx, "container.command.size()"));
		assertEquals(0, evaluate(ctx, "container.args.size()"));
		assertEquals(0, evaluate(ctx, "container.ports.size()"));
		assertEquals(0, evaluate(ctx, "metadata.labels.size()"));
		assertEquals(0, evaluate(ctx, "metadata.annotations.size()"));
		assertEquals(0, evaluate(ctx, "container.securityContext.capabilities.add.size()"));
		assertEquals(0, evaluate(ctx, "container.securityContext.capabilities.drop.size()"));
		assertEquals(0, evaluate(ctx, "securityContext.supplementalGroups.size()"));
	}
}
