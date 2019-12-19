package auth_encryption.primitives;

public enum TrustLevel {
    UNKNOWN, 	// neither seen nor heard of
    KNOWN, 		// people I trust signed him
    TRUSTED, 	// personally signed by me
    ULTIMATE;	// 
}
