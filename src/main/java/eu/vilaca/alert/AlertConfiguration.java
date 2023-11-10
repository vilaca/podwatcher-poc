package eu.vilaca.alert;

import lombok.Data;
import lombok.experimental.Accessors;

@Accessors(fluent = true)
@Data
public class AlertConfiguration {
	private String url;
	private String user;
	private String password;
	private long defaultDuration = 1000 * 60 * 60;
}
