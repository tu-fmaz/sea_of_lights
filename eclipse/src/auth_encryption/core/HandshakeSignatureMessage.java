package auth_encryption.core;

import auth_encryption.primitives.Signature;
import core.DTNHost;

public class HandshakeSignatureMessage extends MessageAuthentication {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public static final int TYPE_HANDSHAKE_SIGNATURE = 0x02;

	private Signature signature = null;

	public HandshakeSignatureMessage(Signature signature, DTNHost to) {
		super(HandshakeSignatureMessage.TYPE_HANDSHAKE_SIGNATURE, to);

		this.signature = signature;
	}

	public Signature getSignature() {
		return this.signature;
	}
}
