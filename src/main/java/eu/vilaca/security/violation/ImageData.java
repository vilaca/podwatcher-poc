package eu.vilaca.security.violation;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class ImageData {
	private final String registry;
	private final String name;
	private final String tag;
	private final String sha256;

	public String pretty() {
		return registry + "/" + name + ":" + tag + "@" + sha256;
	}
}
