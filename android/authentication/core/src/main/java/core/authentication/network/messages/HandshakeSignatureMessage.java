/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.network.messages;

import network.messages.Message;
import primitives.keys.Signature;

/**
 * HandshakeSignatureMessage class implements a Message for sending the signature over the remote key.
 *
 *@author Max Kolhagen
 */
public class HandshakeSignatureMessage extends Message {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static final int TYPE_HANDSHAKE_SIGNATURE = 0x02;

    private Signature signature = null;

    public HandshakeSignatureMessage(Signature signature) {
        super(HandshakeSignatureMessage.TYPE_HANDSHAKE_SIGNATURE);

        this.signature = signature;
    }

    public Signature getSignature() {
        return this.signature;
    }
}
