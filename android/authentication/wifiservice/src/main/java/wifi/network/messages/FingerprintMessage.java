/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi.network.messages;

import network.messages.Message;
import primitives.keys.Fingerprint;

/**
 * FingerprintMessage class implements message which contains only a fingerprint
 *
 *@author Max Kolhagen
 */
public class FingerprintMessage extends Message {
    public static final int TYPE_FINGERPRINT = 0x02;

    private final Fingerprint fingerprint;

    public FingerprintMessage(Fingerprint fingerprint) {
        super(TYPE_FINGERPRINT);

        this.fingerprint = fingerprint;
    }

    public Fingerprint getFingerprint() {
        return this.fingerprint;
    }
}
