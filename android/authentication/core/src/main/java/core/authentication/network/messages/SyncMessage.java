/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.network.messages;

import network.messages.Message;

import java.io.Serializable;
import java.util.Set;

/**
 * SyncMessage class implements a Message containing all related data for the Synchronization.
 *
 *@author Max Kolhagen
 */
public class SyncMessage extends Message {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static final int TYPE_SYNC = 0x11;

    private Set<Serializable> relatedData = null;

    public SyncMessage(Set<Serializable> relatedData) {
        super(SyncMessage.TYPE_SYNC);

        this.relatedData = relatedData;
    }

    public Set<Serializable> getRelatedData() {
        return this.relatedData;
    }
}
