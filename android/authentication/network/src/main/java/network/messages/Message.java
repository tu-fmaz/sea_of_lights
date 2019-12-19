/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package network.messages;

import java.io.Serializable;

/**
 * Message class is the abstract basis class for all network messages.
 *
 *@author Max Kolhagen
 */
public abstract class Message implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static final int TYPE_ALL = 0xFFFFFFFF;
    public static final int TYPE_UNKNOWN = 0x00000000;

    private int type = Message.TYPE_UNKNOWN;

    protected Message(int type) {
        this.type = type;
    }

    public int getType() {
        return this.type;
    }
}
