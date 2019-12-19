package auth_encryption.core;

public class NetworkException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public NetworkException() {
		super();
	}

	public NetworkException(String s) {
		super(s);
	}

	public NetworkException(String message, Throwable cause) {
		super(message, cause);
	}

	public NetworkException(Throwable cause) {
		super(cause);
	}
}
