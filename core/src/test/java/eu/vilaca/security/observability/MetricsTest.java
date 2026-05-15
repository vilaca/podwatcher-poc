package eu.vilaca.security.observability;

import io.prometheus.client.CollectorRegistry;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class MetricsTest {

	@Before
	public void resetMetrics() {
		// Clear all samples so tests are independent
		Metrics.VIOLATIONS_TOTAL.clear();
		Metrics.ALERTS_SENT_TOTAL.clear();
		Metrics.ALERTS_FAILED_TOTAL.clear();
		Metrics.RULES_EVALUATED_TOTAL.clear();
		Metrics.RULES_ERRORS_TOTAL.clear();
		Metrics.PODS_SCANNED_TOTAL.clear();
		Metrics.LAST_SCAN_TIMESTAMP.set(0);
		Metrics.RULES_LOADED.set(0);
	}

	@Test
	public void violationsCounter() {
		Metrics.VIOLATIONS_TOTAL.labels("test-rule").inc();
		Metrics.VIOLATIONS_TOTAL.labels("test-rule").inc();
		assertEquals(2.0, Metrics.VIOLATIONS_TOTAL.labels("test-rule").get(), 0.001);
	}

	@Test
	public void violationsCounterPerRule() {
		Metrics.VIOLATIONS_TOTAL.labels("rule-a").inc();
		Metrics.VIOLATIONS_TOTAL.labels("rule-b").inc();
		Metrics.VIOLATIONS_TOTAL.labels("rule-b").inc();
		assertEquals(1.0, Metrics.VIOLATIONS_TOTAL.labels("rule-a").get(), 0.001);
		assertEquals(2.0, Metrics.VIOLATIONS_TOTAL.labels("rule-b").get(), 0.001);
	}

	@Test
	public void alertsSentCounter() {
		Metrics.ALERTS_SENT_TOTAL.inc();
		assertEquals(1.0, Metrics.ALERTS_SENT_TOTAL.get(), 0.001);
	}

	@Test
	public void alertsFailedCounter() {
		Metrics.ALERTS_FAILED_TOTAL.inc();
		Metrics.ALERTS_FAILED_TOTAL.inc();
		assertEquals(2.0, Metrics.ALERTS_FAILED_TOTAL.get(), 0.001);
	}

	@Test
	public void rulesEvaluatedCounter() {
		Metrics.RULES_EVALUATED_TOTAL.labels("my-rule").inc();
		assertEquals(1.0, Metrics.RULES_EVALUATED_TOTAL.labels("my-rule").get(), 0.001);
	}

	@Test
	public void rulesErrorsCounter() {
		Metrics.RULES_ERRORS_TOTAL.labels("bad-rule").inc();
		assertEquals(1.0, Metrics.RULES_ERRORS_TOTAL.labels("bad-rule").get(), 0.001);
	}

	@Test
	public void podsScannedCounter() {
		Metrics.PODS_SCANNED_TOTAL.inc(10);
		assertEquals(10.0, Metrics.PODS_SCANNED_TOTAL.get(), 0.001);
	}

	@Test
	public void scanDurationSummary() {
		final var countBefore = Metrics.SCAN_DURATION_SECONDS.get().count;
		final var timer = Metrics.SCAN_DURATION_SECONDS.startTimer();
		timer.observeDuration();
		assertTrue(Metrics.SCAN_DURATION_SECONDS.get().count > countBefore);
	}

	@Test
	public void lastScanTimestamp() {
		Metrics.LAST_SCAN_TIMESTAMP.setToCurrentTime();
		assertTrue(Metrics.LAST_SCAN_TIMESTAMP.get() > 0);
	}

	@Test
	public void rulesLoadedGauge() {
		Metrics.RULES_LOADED.set(5);
		assertEquals(5.0, Metrics.RULES_LOADED.get(), 0.001);
	}

	@Test
	public void metricsRegisteredInDefaultRegistry() {
		// All metrics should be in the default registry
		final var samples = CollectorRegistry.defaultRegistry.metricFamilySamples();
		assertTrue(samples.hasMoreElements());
	}
}
