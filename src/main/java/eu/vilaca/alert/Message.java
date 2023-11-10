package eu.vilaca.alert;

import eu.vilaca.violation.PodRuleViolation;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;

@Accessors(fluent = true)
@Data
public class Message {

	private List<Line> content;

	public Message(PodRuleViolation violation) {
		this.content = List.of(new Line(violation));
	}
}
