/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi.network.messages;

import network.messages.Message;
import primitives.keys.Fingerprint;

/**
 * AddressMessage class implements message that contain both the fingerprint and the IP address
 *
 *@author Max Kolhagen
 */
public class AddressMessage extends Message {
    public static final int TYPE_ADDRESS = 0x01;

    private final String address;
    private final Fingerprint fingerprint;

    public AddressMessage(String address, Fingerprint fingerprint) {
        super(TYPE_ADDRESS);

        this.address = address;
        this.fingerprint = fingerprint;
    }

    public String getAddress() {
        return this.address;
    }

    public Fingerprint getFingerprint() {
        return this.fingerprint;
    }
}
