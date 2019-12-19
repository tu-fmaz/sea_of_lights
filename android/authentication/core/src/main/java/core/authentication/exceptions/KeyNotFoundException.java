/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.exceptions;

/**
 * KeyNotFoundException class to manage missing key exceptions
 *
 *@author Max Kolhagen
 */
public class KeyNotFoundException extends KeyManagerException {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public KeyNotFoundException() {
        super();
    }

    public KeyNotFoundException(String s) {
        super(s);
    }

    public KeyNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeyNotFoundException(Throwable cause) {
        super(cause);
    }
}