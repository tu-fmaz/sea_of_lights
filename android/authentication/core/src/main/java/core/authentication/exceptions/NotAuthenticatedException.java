/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.exceptions;

/**
 * NotAuthenticatedException class to manage not authenticated exceptions
 *
 *@author Max Kolhagen
 */
public class NotAuthenticatedException extends KeyManagerException {
	/**
	 *
	 */
	private static final long serialVersionUID = 1L;

	public NotAuthenticatedException() {
		super();
	}

	public NotAuthenticatedException(String s) {
		super(s);
	}

	public NotAuthenticatedException(String message, Throwable cause) {
		super(message, cause);
	}

	public NotAuthenticatedException(Throwable cause) {
		super(cause);
	}
}
