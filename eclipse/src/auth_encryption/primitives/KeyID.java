package auth_encryption.primitives;

import java.io.Serializable;
import java.util.Arrays;

public class KeyID implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public static final int SIZE = 8;

    private byte[] data = null;

    private KeyID() {
        // only visible for generator functions
    }

    public KeyID(byte[] subKey) throws Exception {
        final int len = subKey.length;
        if (len == 0 || len < KeyID.SIZE)
            throw new IllegalArgumentException();

        // determine LSB
        this.data = Arrays.copyOfRange(subKey, len - KeyID.SIZE, len);
    }

    public static KeyID fromData(String hex) {
        return fromData(Utils.hexToBytes(hex));
    }

    public static KeyID fromData(byte[] data) {
        KeyID result = new KeyID();
        result.data = data;

        if (result.data.length != KeyID.SIZE)
            throw new IllegalArgumentException("KeyID has illegal size!");

        return result;
    }

    public byte[] getData() {
        return this.data;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || !(o instanceof KeyID))
            return false;

        if (super.equals(o))
            return true;

        KeyID other = (KeyID) o;

        return Arrays.equals(this.data, other.data);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(this.data);
    }

    @Override
    public String toString() {
        return Utils.bytesToHex(this.data);
    }
}
