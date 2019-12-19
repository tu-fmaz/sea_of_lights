package auth_encryption.primitives;

public enum SignatureParameter {
	RSA("RSA", "SHA256withRSA", 2048),
	ECDSA("ECDSA", "SHA256withECDSA", 256);

	private final String algorithm;
	private final String signatureAlgorithm;
	private final int keySize;
	
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
