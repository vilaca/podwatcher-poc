package eu.vilaca.security.alert.model;

import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Map;

@Accessors(fluent = true)
@Data
public class Message {

	private List<MessageLine> content;

	public Message(Map<String, String> labels) {
		this.content = List.of(new MessageLine(labels));
	}
}
