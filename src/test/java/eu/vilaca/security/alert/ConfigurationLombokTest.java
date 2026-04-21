package eu.vilaca.security.alert;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests Lombok-generated methods on Configuration to improve coverage.
 */
public class ConfigurationLombokTest {

	@Test
	public void toStringContainsFields() {
		final var c = new Configuration()
				.url("http://localhost:9093")
				.user("admin")
				.password("secret");
		final var str = c.toString();
		assertNotNull(str);
		assertTrue(str.contains("localhost"));
		assertTrue(str.contains("admin"));
	}

	@Test
	public void equalsIdentical() {
		final var c1 = new Configuration().url("u").user("a").password("p").defaultDuration(100);
		final var c2 = new Configuration().url("u").user("a").password("p").defaultDuration(100);
		assertEquals(c1, c2);
		assertEquals(c1.hashCode(), c2.hashCode());
	}

	@Test
	public void notEqualDifferentUrl() {
		final var c1 = new Configuration().url("a");
		final var c2 = new Configuration().url("b");
		assertNotEquals(c1, c2);
	}

	@Test
	public void notEqualDifferentUser() {
		final var c1 = new Configuration().url("u").user("a");
		final var c2 = new Configuration().url("u").user("b");
		assertNotEquals(c1, c2);
	}

	@Test
	public void notEqualDifferentPassword() {
		final var c1 = new Configuration().url("u").user("a").password("p1");
		final var c2 = new Configuration().url("u").user("a").password("p2");
		assertNotEquals(c1, c2);
	}

	@Test
	public void notEqualDifferentDuration() {
		final var c1 = new Configuration().defaultDuration(100);
		final var c2 = new Configuration().defaultDuration(200);
		assertNotEquals(c1, c2);
	}

	@Test
	public void equalsNull() {
		assertNotEquals(null, new Configuration());
	}

	@Test
	public void equalsSelf() {
		final var c = new Configuration();
		assertEquals(c, c);
	}

	@Test
	public void equalsDifferentType() {
		assertNotEquals("string", new Configuration());
	}

	@Test
	public void defaultValues() {
		final var c = new Configuration();
		assertNull(c.url());
		assertNull(c.user());
		assertNull(c.password());
		assertEquals(300000, c.defaultDuration());
	}

	@Test
	public void fluentSettersReturnSameInstance() {
		final var c = new Configuration();
		assertSame(c, c.url("test"));
		assertSame(c, c.user("test"));
		assertSame(c, c.password("test"));
		assertSame(c, c.defaultDuration(1));
	}
}
