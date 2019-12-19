/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.network.messages;

import network.messages.Message;
import primitives.keys.Fingerprint;

import java.util.Set;

/**
 * SyncRequestMessage class implements a Message for triggering the Synchronization.
 *
 *@author Max Kolhagen
 */
public class SyncRequestMessage extends Message {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static final int TYPE_SYNC_REQUEST = 0x10;

    private Set<Fingerprint> subjects = null;

    public SyncRequestMessage(Set<Fingerprint> subjects) {
        super(SyncRequestMessage.TYPE_SYNC_REQUEST);

        this.subjects = subjects;
    }

    public Set<Fingerprint> getTrustedSubjects() {
        return this.subjects;
    }
}

