/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.trust;

import java.io.Serializable;

/**
 * TrustInfo class handles information about trust
 * Trust is represented through the level of trust (signed by whom) and the degree of
 * trust (length of certification path -or- distance).
 *
 *@author Max Kolhagen
 */
public class TrustInfo implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public static final TrustInfo UNKNOWN = new TrustInfo();
	
	public TrustLevel level = TrustLevel.UNKNOWN;	// level of trust
	public int degree = -1; 						// length of the certification path (to further distinguish level K)
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + degree;
		result = prime * result + ((level == null) ? 0 : level.hashCode());
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
		TrustInfo other = (TrustInfo) obj;
		if (degree != other.degree)
			return false;
		if (level != other.level)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "TrustInfo [level=" + level + ", degree=" + degree + "]";
	}
}
