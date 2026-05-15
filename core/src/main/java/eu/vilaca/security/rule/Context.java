package eu.vilaca.security.rule;

import eu.vilaca.security.violation.ImageData;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class Context {
	public Container container;
	public Spec spec;
	public PodSecurityContext securityContext;
	public Metadata metadata;

	public static class Metadata {
		public String name;
		public String namespace;
		public Map<String, String> labels = Collections.emptyMap();
		public Map<String, String> annotations = Collections.emptyMap();
	}

	public static class PodSecurityContext {
		public Long runAsGroup;
		public Boolean runAsNonRoot;
		public Long runAsUser;
		public Long fsGroup;
		public List<Long> supplementalGroups = Collections.emptyList();
		public String seccompProfileType;
	}

	public static class ContainerSecurityContext {
		public Boolean allowPrivilegeEscalation;
		public Boolean privileged;
		public Boolean readOnlyRootFilesystem;
		public Long runAsGroup;
		public Boolean runAsNonRoot;
		public Long runAsUser;
		public Capabilities capabilities;
		public String seccompProfileType;
		public String procMount;
	}

	public static class Capabilities {
		public List<String> add = Collections.emptyList();
		public List<String> drop = Collections.emptyList();
	}

	public static class Container {
		public ImageData image;
		public ContainerSecurityContext securityContext;
		public String name;
		public List<String> command = Collections.emptyList();
		public List<String> args = Collections.emptyList();
		public List<Integer> ports = Collections.emptyList();
		public String containerType;
	}

	public static class Spec {
		public Boolean hostPID;
		public Boolean hostNetwork;
		public Boolean hostIPC;
		public String serviceAccountName;
		public Boolean automountServiceAccountToken;
	}
}
