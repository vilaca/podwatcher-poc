package eu.vilaca.security.observability;

import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Summary;

public class Metrics {

	public static final Counter VIOLATIONS_TOTAL = Counter.build()
			.name("podwatcher_violations_total")
			.help("Total number of rule violations detected.")
			.labelNames("rule")
			.register();

	public static final Counter ALERTS_SENT_TOTAL = Counter.build()
			.name("podwatcher_alerts_sent_total")
			.help("Total number of alerts successfully sent to AlertManager.")
			.register();

	public static final Counter ALERTS_FAILED_TOTAL = Counter.build()
			.name("podwatcher_alerts_failed_total")
			.help("Total number of alerts that failed to send after all retries.")
			.register();

	public static final Counter RULES_EVALUATED_TOTAL = Counter.build()
			.name("podwatcher_rules_evaluated_total")
			.help("Total number of rule evaluations performed.")
			.labelNames("rule")
			.register();

	public static final Counter RULES_ERRORS_TOTAL = Counter.build()
			.name("podwatcher_rules_errors_total")
			.help("Total number of rule evaluation errors.")
			.labelNames("rule")
			.register();

	public static final Counter PODS_SCANNED_TOTAL = Counter.build()
			.name("podwatcher_pods_scanned_total")
			.help("Total number of pods scanned.")
			.register();

	public static final Summary SCAN_DURATION_SECONDS = Summary.build()
			.name("podwatcher_scan_duration_seconds")
			.help("Time spent on a complete scan cycle.")
			.register();

	public static final Gauge LAST_SCAN_TIMESTAMP = Gauge.build()
			.name("podwatcher_last_scan_timestamp_seconds")
			.help("Unix timestamp of the last completed scan.")
			.register();

	public static final Gauge RULES_LOADED = Gauge.build()
			.name("podwatcher_rules_loaded")
			.help("Number of rules currently loaded.")
			.register();

	private Metrics() {
	}
}
