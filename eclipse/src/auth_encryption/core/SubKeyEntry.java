package auth_encryption.core;

import java.io.Serializable;
import java.util.Arrays;

import auth_encryption.primitives.SubKeySignature;

public class SubKeyEntry implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

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
