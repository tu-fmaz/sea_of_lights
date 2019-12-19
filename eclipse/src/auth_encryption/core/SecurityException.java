package auth_encryption.core;

public class SecurityException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public SecurityException() {
		super();
	}

	public SecurityException(String s) {
		super(s);
	}

	public SecurityException(String message, Throwable cause) {
		super(message, cause);
	}

	public SecurityException(Throwable cause) {
		super(cause);
	}
}
