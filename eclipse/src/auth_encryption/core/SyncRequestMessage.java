package auth_encryption.core;

import java.util.Set;

import auth_encryption.primitives.Fingerprint;
import core.DTNHost;

public class SyncRequestMessage extends MessageAuthentication {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public static final int TYPE_SYNC_REQUEST = 0x10;

	private Set<Fingerprint> subjects = null;

	public SyncRequestMessage(Set<Fingerprint> subjects, DTNHost to) {
		super(SyncRequestMessage.TYPE_SYNC_REQUEST, to);

		this.subjects = subjects;
	}

	public Set<Fingerprint> getTrustedSubjects() {
		return this.subjects;
	}
}
