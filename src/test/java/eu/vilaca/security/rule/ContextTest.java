package eu.vilaca.security.rule;

import eu.vilaca.security.violation.ImageData;
import org.junit.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import static org.junit.Assert.*;

/**
 * Tests the Context class and its nested classes, including SpEL evaluation
 * against Context objects (which is how rules work at runtime).
 */
public class ContextTest {

	private final SpelExpressionParser parser = new SpelExpressionParser();

	private Object evaluate(Context ctx, String expression) {
		final var evalCtx = new StandardEvaluationContext(ctx);
		return parser.parseExpression(expression).getValue(evalCtx);
	}

	// --- Container image access ---

	@Test
	public void spelCanAccessImageRegistry() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();

		assertEquals("docker.io", evaluate(ctx, "container.image.registry"));
	}

	@Test
	public void spelCanAccessImageName() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("ghcr.io/org/myapp:v1");
		ctx.container.securityContext = new Context.ContainerSecurityContext();

		assertEquals("myapp", evaluate(ctx, "container.image.name"));
	}

	@Test
	public void spelCanAccessImageTag() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:1.25");
		ctx.container.securityContext = new Context.ContainerSecurityContext();

		assertEquals("1.25", evaluate(ctx, "container.image.tag"));
	}

	// --- Container security context ---

	@Test
	public void spelCanAccessPrivileged() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.privileged = true;

		assertEquals(true, evaluate(ctx, "container.securityContext.privileged == true"));
	}

	@Test
	public void spelPrivilegedFalse() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.privileged = false;

		assertEquals(false, evaluate(ctx, "container.securityContext.privileged == true"));
	}

	@Test
	public void spelCanAccessAllowPrivilegeEscalation() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.allowPrivilegeEscalation = true;

		assertEquals(true, evaluate(ctx, "container.securityContext.allowPrivilegeEscalation == true"));
	}

	@Test
	public void spelCanAccessReadOnlyRootFilesystem() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.readOnlyRootFilesystem = false;

		assertEquals(true, evaluate(ctx, "container.securityContext.readOnlyRootFilesystem == false"));
	}

	@Test
	public void spelCanAccessContainerRunAsUser() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.runAsUser = 0L;

		assertEquals(true, evaluate(ctx, "container.securityContext.runAsUser == 0"));
	}

	// --- Pod security context ---

	@Test
	public void spelCanAccessPodRunAsUser() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.securityContext = new Context.PodSecurityContext();
		ctx.securityContext.runAsUser = 0L;

		assertEquals(true, evaluate(ctx, "securityContext.runAsUser == 0"));
	}

	@Test
	public void spelCanAccessPodRunAsGroup() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.securityContext = new Context.PodSecurityContext();
		ctx.securityContext.runAsGroup = 1000L;

		assertEquals(1000L, evaluate(ctx, "securityContext.runAsGroup"));
	}

	@Test
	public void spelCanAccessPodRunAsNonRoot() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.securityContext = new Context.PodSecurityContext();
		ctx.securityContext.runAsNonRoot = true;

		assertEquals(true, evaluate(ctx, "securityContext.runAsNonRoot"));
	}

	// --- Spec ---

	@Test
	public void spelCanAccessHostPID() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.spec = new Context.Spec();
		ctx.spec.hostPID = true;

		assertEquals(true, evaluate(ctx, "spec.hostPID == true"));
	}

	@Test
	public void spelHostPIDFalse() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.spec = new Context.Spec();
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
		// ctx.securityContext is null

		// Accessing null securityContext should throw SpelEvaluationException
		try {
			evaluate(ctx, "securityContext.runAsUser == 0");
			fail("Expected exception for null securityContext");
		} catch (Exception e) {
			// Expected
		}
	}

	@Test
	public void spelNullPrivilegedField() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		// privileged is null

		// null == true should be false in SpEL
		assertEquals(false, evaluate(ctx, "container.securityContext.privileged == true"));
	}

	// --- Compound expressions ---

	@Test
	public void compoundOrExpression() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.privileged = true;
		ctx.container.securityContext.allowPrivilegeEscalation = false;

		assertEquals(true, evaluate(ctx,
				"container.securityContext.privileged == true || container.securityContext.allowPrivilegeEscalation == true"));
	}

	@Test
	public void compoundAndExpression() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.privileged = true;
		ctx.container.securityContext.allowPrivilegeEscalation = true;

		assertEquals(true, evaluate(ctx,
				"container.securityContext.privileged == true && container.securityContext.allowPrivilegeEscalation == true"));
	}

	@Test
	public void registryComparisonExpression() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();

		assertEquals(true, evaluate(ctx,
				"container.image.registry != 'registry.k8s.io'"));
	}

	@Test
	public void multiRegistryCompoundExpression() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("quay.io/prometheus/node-exporter");
		ctx.container.securityContext = new Context.ContainerSecurityContext();

		assertEquals(true, evaluate(ctx,
				"container.image.registry != 'registry.k8s.io' " +
						"&& container.image.registry != 'docker.io' " +
						"&& container.image.registry != 'ghcr.io'"));
	}

	@Test
	public void multiRegistryCompoundExpression_matchesOneRegistry() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();

		assertEquals(false, evaluate(ctx,
				"container.image.registry != 'registry.k8s.io' " +
						"&& container.image.registry != 'docker.io' " +
						"&& container.image.registry != 'ghcr.io'"));
	}
}
