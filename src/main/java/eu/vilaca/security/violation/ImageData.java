package eu.vilaca.security.violation;

import lombok.Data;

@Data
public class ImageData {
	private final String registry;
	private final String name;
	private final String tag;
	private final String sha256;

	public ImageData(String image) {
		if (image == null) {
			registry = name = tag = sha256 = null;
			return;
		}

		this.registry = image.substring(0, image.indexOf('/'));
		final var tag = image.indexOf(':');
		final var sha256 = image.indexOf('@');

		if (tag == -1 && sha256 == -1) {
			this.name = image.substring(image.lastIndexOf('/') + 1);
		} else if (tag != -1) {
			this.name = image.substring(image.lastIndexOf('/') + 1, tag);
		} else {
			this.name = image.substring(image.lastIndexOf('/') + 1, sha256);
		}

		if (tag != -1 && sha256 != -1) {
			this.tag = image.substring(tag + 1);
			this.sha256 = image.substring(sha256 + 1);
		} else if (sha256 != -1) {
			this.tag = null;
			this.sha256 = image.substring(sha256 + 1);
		} else {
			this.tag = null;
			this.sha256 = null;
		}
	}

	public String pretty() {
		var name = this.registry + "/" + this.name;
		if (tag != null) {
			name += ":" + tag;
		}
		if (sha256 != null) {
			name += ":" + sha256;
		}
		return name;
	}
}
