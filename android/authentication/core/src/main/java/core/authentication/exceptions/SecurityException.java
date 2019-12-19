/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.exceptions;

/**
 * SecurityException class to manage security exceptions
 *
 *@author Max Kolhagen
 */
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
