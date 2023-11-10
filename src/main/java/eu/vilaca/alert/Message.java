package eu.vilaca.alert;

import eu.vilaca.violation.PodRuleViolation;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Map;

/* Example:
[{"labels":{"alertname":"oooops! there goes the afternoon", "system":"all"},"endsAt":"2023-11-21T00:10:53-03:00"}]
* */

@Accessors(fluent = true)
@Data
public class Message {

	private List<Line> content;

	public Message(PodRuleViolation violation) {
		this.content = List.of(new Line(violation));
	}
}
