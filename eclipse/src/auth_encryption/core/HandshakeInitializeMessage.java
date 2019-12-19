package auth_encryption.core;

import java.security.PublicKey;

import auth_encryption.primitives.Signature;
import core.DTNHost;

public class HandshakeInitializeMessage extends MessageAuthentication {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	// There are two different types of handshake! 
	// First is the initialization 
	// Second is the exchange of signatures
	// Message allows to choose between both possibilities 
	public static final int TYPE_HANDSHAKE_INIT = 0x01;

	private PublicKey publicKey = null;
	private Signature signature = null;
	private boolean response = false;

	public HandshakeInitializeMessage(PublicKey publicKey, Signature signature, DTNHost to) {
		super(HandshakeInitializeMessage.TYPE_HANDSHAKE_INIT, to);

		this.publicKey = publicKey;
		this.signature = signature;
	}

	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	public Signature getSignature() {
		return this.signature;
	}

	public boolean isResponse() {
		return response;
	}

	public void setResponse(boolean response) {
		this.response = response;
	}
}
