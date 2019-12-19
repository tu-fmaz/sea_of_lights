/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.network.messages;

import java.security.PublicKey;

import network.messages.Message;
import primitives.keys.Signature;

/**
 * HandshakeInitializeMessage class implements a Message for initializing the Handshake.
 *
 *@author Max Kolhagen
 */
public class HandshakeInitializeMessage extends Message {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public static final int TYPE_HANDSHAKE_INIT = 0x01;

	private PublicKey publicKey = null;
	private Signature signature = null;
	private boolean response = false;

	public HandshakeInitializeMessage(PublicKey publicKey, Signature signature) {
		super(HandshakeInitializeMessage.TYPE_HANDSHAKE_INIT);

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
