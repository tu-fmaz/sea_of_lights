package auth_encryption.primitives;

import applications.AuthenticationApplication;

public abstract class Config {
	private Config() {
		// hide
	}

	public static final String TRUST_PATH = "trust/";
	// public static final long TRUST_TRIGGER_UPDATE_INTERVAL = 12 * 60 * 60 * 1000; // 12h
	public static final boolean TRUST_EXTRA_SECURITY = true; // for TFM load operations
	//public static int TRUST_MAX_DEGREE = AuthenticationApplication.TRUST_DEGREE;
	public static final int TRUST_NUM_KNOWN_REQUIRED = 3;
	public static final long TRUST_HANDSHAKE_TIMEOUT = 5 * 60 * 1000; // 5min
	public static final int TRUST_MAX_META_ALIASES = 5;
	public static final int TRUST_MAX_SUB_KEY_PER_APP = 5;
	
	//public static SignatureParameter KEY_SIGNATURE_PARAMETERS = AuthenticationApplication.KEY_PARAMETER;
}
