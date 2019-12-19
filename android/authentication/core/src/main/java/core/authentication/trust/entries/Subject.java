/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.trust.entries;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import primitives.keys.Fingerprint;
import primitives.keys.KeyID;
import primitives.keys.Signature;
import primitives.trust.TrustInfo;

/**
 * Subject class represents a single subject/entity in the trust repository.
 *
 *@author Max Kolhagen
 */
public class Subject {
    /**
     * FIELDS
     */

	public PublicKey publicKey = null;
	public Fingerprint fingerprint = null;
	/* issued for this subject */
	public Set<Signature> issuers = new HashSet<>();
	/* issued by this subject */
	public Set<Signature> issued = new HashSet<>();
	public Map<KeyID, SubKeyEntry> subKeys = new HashMap<>();
	public TrustInfo trustInfo = new TrustInfo();
	public long lastSynchronization = 0;

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((fingerprint == null) ? 0 : fingerprint.hashCode());
		result = prime * result + ((issued == null) ? 0 : issued.hashCode());
		result = prime * result + ((issuers == null) ? 0 : issuers.hashCode());
		result = prime * result + ((subKeys == null) ? 0 : subKeys.hashCode());
		result = prime * result + ((trustInfo == null) ? 0 : trustInfo.hashCode());
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
		Subject other = (Subject) obj;
		if (fingerprint == null) {
			if (other.fingerprint != null)
				return false;
		} else if (!fingerprint.equals(other.fingerprint))
			return false;
		if (issued == null) {
			if (other.issued != null)
				return false;
		} else if (!issued.equals(other.issued))
			return false;
		if (issuers == null) {
			if (other.issuers != null)
				return false;
		} else if (!issuers.equals(other.issuers))
			return false;
		if (subKeys == null) {
			if (other.subKeys != null)
				return false;
		} else if (!subKeys.equals(other.subKeys))
			return false;
		if (trustInfo == null) {
			if (other.trustInfo != null)
				return false;
		} else if (!trustInfo.equals(other.trustInfo))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "Subject [fingerprint=" + fingerprint + ", issuers=" + issuers + ", issued=" + issued + ", subKeys="
				+ subKeys + ", trustInfo=" + trustInfo + "]";
	}
}