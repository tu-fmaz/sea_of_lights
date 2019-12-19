package auth_encryption.primitives;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;

public class Fingerprint implements Serializable {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private static final byte TAG = (byte) 0x99;
    public static final int SIZE = 32;

    private byte[] data = null;

    private Fingerprint() {
        // only visible for generator functions
    }

    public Fingerprint(PublicKey publicKey) throws Exception {
        this(publicKey.getEncoded());
    }

    public Fingerprint(byte[] publicKey) throws Exception {
        if (publicKey.length == 0)
            throw new IllegalArgumentException();

        MessageDigest md = MessageDigest.getInstance("SHA256");
        md.update(Fingerprint.TAG);
        md.update(Utils.intBytes(publicKey.length));
        md.update(publicKey);
        this.data = md.digest();
    }

    public static Fingerprint fromData(String hex) {
        return fromData(Utils.hexToBytes(hex));
    }

    public static Fingerprint fromData(byte[] data) {
        Fingerprint result = new Fingerprint();
        result.data = data;

        if (result.data.length != Fingerprint.SIZE)
            throw new IllegalArgumentException("Fingerprint has illegal size!");

        return result;
    }

    public byte[] getData() {
        return this.data;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || !(o instanceof Fingerprint))
            return false;

        if (super.equals(o))
            return true;

        Fingerprint other = (Fingerprint) o;

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
