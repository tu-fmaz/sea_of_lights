/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.keys;

import primitives.config.Config;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Date;

/**
 * Signature class represents the certificate over a public key.
 *
 *@author Max Kolhagen
 */
public class Signature implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    /**
     * FIELDS
     */
    private Date time = null;

    private Fingerprint issuer = null;
    private Fingerprint subject = null;

    private String alias = null;

    /**
     * SIGNATURE
     */
    private byte[] data = null; // contains sign(hash(all fields + public key to be signed))

    /**
     * Constructor.
     *
     * @param issuer
     * @param subject
     * @throws Exception
     */
    public Signature(PublicKey issuer, PublicKey subject) throws Exception {
        if (issuer == null || subject == null)
            throw new IllegalArgumentException();

        this.time = new Date();
        this.issuer = new Fingerprint(issuer);
        this.subject = new Fingerprint(subject);
    }

    /**
     * Verify the certificate.
     *
     * @param issuer
     * @param subject
     * @return
     * @throws Exception
     */
    public boolean verify(PublicKey issuer, PublicKey subject) throws Exception {
        if (issuer == null || subject == null)
            throw new IllegalArgumentException();

        if (this.data == null || this.data.length == 0)
            throw new IllegalStateException("Certificate is not signed!");

        // check if fingerprints are correct
        Fingerprint fpIssuer = new Fingerprint(issuer);
        Fingerprint fpSubject = new Fingerprint(subject);

        if (!this.issuer.equals(fpIssuer) || !this.subject.equals(fpSubject))
            throw new SignatureException("Fingerprints do not match!");

        java.security.Signature sig = java.security.Signature.getInstance(Config.KEY_SIGNATURE_PARAMETERS.getSignatureAlgorithm());
        sig.initVerify(issuer);
        sig.update(this.getDigestData(subject));
        return sig.verify(this.data);
    }

    /**
     * Gather all digest data that goes into the signature.
     *
     * @param subject
     * @return
     * @throws Exception
     */
    public byte[] getDigestData(PublicKey subject) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        ByteBuffer timeBuffer = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
        timeBuffer.putLong(this.time.getTime());
        md.update(timeBuffer.array());
        md.update(this.issuer.getData());
        md.update(this.subject.getData());
        md.update(subject.getEncoded());
        if (this.alias != null)
            md.update(this.alias.getBytes("UTF-8"));

        return md.digest();
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public byte[] getData() {
        return this.data;
    }

    public Fingerprint getIssuer() {
        return this.issuer;
    }

    public Fingerprint getSubject() {
        return this.subject;
    }

    public Date getTime() {
        return this.time;
    }

    public String getAlias() {
        return this.alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((alias == null) ? 0 : alias.hashCode());
        result = prime * result + Arrays.hashCode(data);
        result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
        result = prime * result + ((subject == null) ? 0 : subject.hashCode());
        result = prime * result + ((time == null) ? 0 : time.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Signature other = (Signature) obj;
        if (alias == null) {
            if (other.alias != null)
                return false;
        } else if (!alias.equals(other.alias))
            return false;
        if (!Arrays.equals(data, other.data))
            return false;
        if (issuer == null) {
            if (other.issuer != null)
                return false;
        } else if (!issuer.equals(other.issuer))
            return false;
        if (subject == null) {
            if (other.subject != null)
                return false;
        } else if (!subject.equals(other.subject))
            return false;
        if (time == null) {
            if (other.time != null)
                return false;
        } else if (!time.equals(other.time))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "Signature [time=" + time + ", issuer=" + issuer + ", subject=" + subject + ", alias=" + alias + "]";
    }
}
