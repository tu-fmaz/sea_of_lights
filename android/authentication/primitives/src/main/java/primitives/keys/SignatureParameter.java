/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.keys;

/**
 * SignatureParameter class stores the different signature algorithms that are currently available
 *
 *@author Max Kolhagen
 */
public enum SignatureParameter {
    RSA("RSA", "SHA256withRSA", 2048),
    ECDSA("EC", "SHA256withECDSA", 256);

    /**
     * FIELDS
     */
    private final String algorithm;
    private final String signatureAlgorithm;
    private final int keySize;

    /**
     * Constructor.
     *
     * @param algorithm
     * @param signatureAlgorithm
     * @param keySize
     */
    SignatureParameter(final String algorithm, final String signatureAlgorithm, final int keySize) {
        this.algorithm = algorithm;
        this.signatureAlgorithm = signatureAlgorithm;
        this.keySize = keySize;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public int getKeySize() {
        return this.keySize;
    }
}
