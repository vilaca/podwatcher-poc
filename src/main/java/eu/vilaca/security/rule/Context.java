package eu.vilaca.security.rule;

import eu.vilaca.security.violation.ImageData;

public class Context {
	public Container container;
	public Spec spec;
	public PodSecurityContext securityContext;

	public static class PodSecurityContext {
		public Long runAsGroup;
		public Boolean runAsNonRoot;
		public Long runAsUser;
	}

	public static class ContainerSecurityContext {
		public Boolean allowPrivilegeEscalation;
		public Boolean privileged;
		public Boolean readOnlyRootFilesystem;
		public Long runAsGroup;
		public Boolean runAsNonRoot;
		public Long runAsUser;
	}

	public static class Container {
		public ImageData image;
		public ContainerSecurityContext securityContext;
	}

	public static class Spec {
		public Boolean hostPID;
	}
}
