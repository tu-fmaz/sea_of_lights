/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.exceptions;

/**
 * NetworkException class to manage network exceptions
 *
 *@author Max Kolhagen
 */
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
