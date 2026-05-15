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

		final var lastSlash = image.lastIndexOf('/');

		if (lastSlash == -1) {
			this.registry = null;
		} else {
			this.registry = image.substring(0, lastSlash);
		}

		final var nameStart = lastSlash + 1;
		final var namePart = image.substring(nameStart);

		final var atPos = namePart.indexOf('@');
		final var colonPos = namePart.indexOf(':');

		// colon is only a tag separator if it appears before '@' (or there's no '@')
		final var hasTag = colonPos != -1 && (atPos == -1 || colonPos < atPos);

		if (!hasTag && atPos == -1) {
			this.name = namePart;
			this.tag = null;
			this.sha256 = null;
		} else if (!hasTag) {
			this.name = namePart.substring(0, atPos);
			this.tag = null;
			this.sha256 = namePart.substring(atPos + 1);
		} else if (atPos == -1) {
			this.name = namePart.substring(0, colonPos);
			this.tag = namePart.substring(colonPos + 1);
			this.sha256 = null;
		} else {
			this.name = namePart.substring(0, colonPos);
			this.tag = namePart.substring(colonPos + 1, atPos);
			this.sha256 = namePart.substring(atPos + 1);
		}
	}

	public String pretty() {
		var name = this.registry != null ? this.registry + "/" + this.name : this.name;
		if (tag != null) {
			name += ":" + tag;
		}
		if (sha256 != null) {
			name += "@" + sha256;
		}
		return name;
	}
}
