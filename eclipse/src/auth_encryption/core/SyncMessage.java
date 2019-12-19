package auth_encryption.core;

import java.io.Serializable;
import java.util.Set;

import core.DTNHost;

public class SyncMessage extends MessageAuthentication {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static final int TYPE_SYNC = 0x11;

    private Set<Serializable> relatedData = null;

    public SyncMessage(Set<Serializable> relatedData, DTNHost to) {
        super(SyncMessage.TYPE_SYNC, to);
        this.relatedData = relatedData;
    }

    public Set<Serializable> getRelatedData() {
        return this.relatedData;
    }
}
