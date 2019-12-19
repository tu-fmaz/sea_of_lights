package auth_encryption.primitives;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import applications.AuthenticationApplication;

public class SubKeySignature implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public static AtomicInteger COUNT = new AtomicInteger(0);

	private final Date time;

	private final Fingerprint owner;
	private final KeyID subKey;

	private final AppDetails appAuth;

	private String tag = null; // make searchable tag

	private byte[] data = null; // contains sign(hash(all fields + public key to
	// be signed))

	public SubKeySignature(PublicKey owner, byte[] subKey, AppDetails details) throws Exception {
		if (owner == null || subKey == null || details == null)
			throw new IllegalArgumentException();

		this.time = new Date();
		this.owner = new Fingerprint(owner);
		this.subKey = new KeyID(subKey);

		// make copy
		this.appAuth = new AppDetails(details.packageName);
		this.appAuth.signatureKeyFingerprint = details.signatureKeyFingerprint;
	}

	public boolean verify(PublicKey owner, byte[] subKey) throws Exception {
		if (owner == null || subKey == null)
			throw new IllegalArgumentException();

		if (this.data == null || this.data.length == 0)
			throw new IllegalStateException("Certificate is not signed!");

		// check if fingerprints are correct
		Fingerprint fpOwner = new Fingerprint(owner);
		KeyID idSubject = new KeyID(subKey);

		if (!this.owner.equals(fpOwner) || !this.subKey.equals(idSubject))
			throw new SignatureException("Fingerprints do not match!");

		COUNT.incrementAndGet();

		java.security.Signature sig = java.security.Signature
				.getInstance(AuthenticationApplication.KEY_PARAMETER.getSignatureAlgorithm());
		sig.initVerify(owner);
		sig.update(this.getDigestData(subKey));
		return sig.verify(this.data);
	}

	public byte[] getDigestData(byte[] subKey) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		ByteBuffer timeBuffer = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
		timeBuffer.putLong(this.time.getTime());
		md.update(timeBuffer.array());
		md.update(this.owner.getData());
		md.update(this.subKey.getData());
		md.update(this.appAuth.packageName.getBytes("UTF-8"));
		if (this.appAuth.signatureKeyFingerprint != null)
			md.update(this.appAuth.signatureKeyFingerprint.getData());
		if (this.tag != null)
			md.update(this.tag.getBytes("UTF-8"));
		md.update(subKey);

		return md.digest();
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public byte[] getData() {
		return this.data;
	}

	public Fingerprint getOwner() {
		return this.owner;
	}

	public KeyID getSubKey() {
		return this.subKey;
	}

	public Date getTime() {
		return this.time;
	}

	public AppDetails getAppAuthentication() {
		return this.appAuth;
	}

	public void setTag(String tag) {
		this.tag = tag;
	}

	public String getTag() {
		return this.tag;
	}

	public void setBindToApp(boolean bindToApp) {
		if (!bindToApp)
			this.appAuth.signatureKeyFingerprint = null;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((appAuth == null) ? 0 : appAuth.hashCode());
		result = prime * result + Arrays.hashCode(data);
		result = prime * result + ((owner == null) ? 0 : owner.hashCode());
		result = prime * result + ((subKey == null) ? 0 : subKey.hashCode());
		result = prime * result + ((tag == null) ? 0 : tag.hashCode());
		result = prime * result + ((time == null) ? 0 : time.hashCode());
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
		SubKeySignature other = (SubKeySignature) obj;
		if (appAuth == null) {
			if (other.appAuth != null)
				return false;
		} else if (!appAuth.equals(other.appAuth))
			return false;
		if (!Arrays.equals(data, other.data))
			return false;
		if (owner == null) {
			if (other.owner != null)
				return false;
		} else if (!owner.equals(other.owner))
			return false;
		if (subKey == null) {
			if (other.subKey != null)
				return false;
		} else if (!subKey.equals(other.subKey))
			return false;
		if (tag == null) {
			if (other.tag != null)
				return false;
		} else if (!tag.equals(other.tag))
			return false;
		if (time == null) {
			if (other.time != null)
				return false;
		} else if (!time.equals(other.time))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "SubKeySignature [time=" + time + ", owner=" + owner + ", subKey=" + subKey + ", appAuth=" + appAuth
				+ ", tag=" + tag + ", data=" + Arrays.toString(data) + "]";
	}
}
