package eu.vilaca.security.alert;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.Setter;
import lombok.experimental.Accessors;

@Data
@Accessors(fluent = true)
@Setter(onMethod = @__(@JsonProperty))
public class Configuration {
	private String url;
	private String user;
	private String password;
	private long defaultDuration = 1000 * 60 * 5;
}
