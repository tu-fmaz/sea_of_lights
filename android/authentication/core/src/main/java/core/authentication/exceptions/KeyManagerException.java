/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */

package core.authentication.exceptions;

/**
 * KeyManagerException class to manage keymanager exceptions
 *
 *@author Max Kolhagen
 */
public class KeyManagerException extends Exception {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public KeyManagerException() {
        super();
    }

    public KeyManagerException(String s) {
        super(s);
    }

    public KeyManagerException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeyManagerException(Throwable cause) {
        super(cause);
    }
}