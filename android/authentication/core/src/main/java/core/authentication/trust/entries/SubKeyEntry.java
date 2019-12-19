/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.trust.entries;

import java.io.Serializable;
import java.util.Arrays;

import primitives.keys.SubKeySignature;

/**
 * SubKeyEntry class summarizes a sub key by its public key and signature certificate.
 *
 *@author Max Kolhagen
 */
public class SubKeyEntry implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

    /**
     * FIELDS
     */
	public byte[] publicKey = null;
	public SubKeySignature signature = null;

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(publicKey);
		result = prime * result + ((signature == null) ? 0 : signature.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SubKeyEntry other = (SubKeyEntry) obj;
		if (!Arrays.equals(publicKey, other.publicKey))
			return false;
		if (signature == null) {
			if (other.signature != null)
				return false;
		} else if (!signature.equals(other.signature))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SubKeyEntry [signature=" + signature + "]";
	}
}
