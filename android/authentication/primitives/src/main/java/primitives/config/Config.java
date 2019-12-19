/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.config;

import primitives.keys.SignatureParameter;

/**
 * Config class implements configuration for the sol- service and all of its components.
 *
 *@author Max Kolhagen
 */
public abstract class Config {
	private Config() {
		// hide
	}

	/**
	 * NETWORK
	 */
	public static final int NETWORK_PORT = 4240;
	public static final int NETWORK_WIFI_PORT = 4242;
	public static final int NETWORK_TIMEOUT = 5000;

	/**
	 * TRUST
	 */
	public static final String TRUST_PATH = "trust/";
	public static final boolean TRUST_EXTRA_SECURITY = true; // for TFM load operations
	public static final int TRUST_MAX_DEGREE = 3;
	public static final int TRUST_NUM_KNOWN_REQUIRED = 3;
	public static final long TRUST_HANDSHAKE_TIMEOUT = 5 * 60 * 1000; // 5min
	public static final int TRUST_MAX_META_ALIASES = 5;
	public static final int TRUST_MAX_SUB_KEY_PER_APP = 5;

	/**
	 * KEYS
	 */
	public static final SignatureParameter KEY_SIGNATURE_PARAMETERS = SignatureParameter.ECDSA;
}
