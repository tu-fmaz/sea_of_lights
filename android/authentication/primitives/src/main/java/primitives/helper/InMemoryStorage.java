/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.helper;

import java.util.HashMap;

/**
 * InMemoryStorage class implements In-memory storage as a singleton object.
 *
 *@author Max Kolhagen
 */
public final class InMemoryStorage extends HashMap<String, Object> {
    private static final String TAG = InMemoryStorage.class.getSimpleName();

    public static final String PASSWORD = "password";
    public static final String FINGERPRINT = "fingerprint";

    private InMemoryStorage() {
        // hide
    }

    // ---- SINGLETON

    private static InMemoryStorage _instance = null;

    public static final synchronized InMemoryStorage getInstance() {
        if (_instance == null)
            _instance = new InMemoryStorage();

        return _instance;
    }
}
