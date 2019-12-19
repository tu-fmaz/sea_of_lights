/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.trust;

/**
 * TrustLevel enum indicates the level of trust towards an entity.
 *
 *@author Max Kolhagen
 */
public enum TrustLevel {
    UNKNOWN, 	// neither seen nor heard of
    KNOWN, 		// people I trust signed him
    TRUSTED, 	// personally signed by me
    ULTIMATE	//
}
