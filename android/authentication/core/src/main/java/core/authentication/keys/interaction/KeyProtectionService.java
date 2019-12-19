
/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.interaction;

import android.app.IntentService;
import android.content.Intent;
import android.util.Log;

import core.authentication.keys.KeyManagerPriority;
import core.authentication.trust.ManagerService;
import primitives.helper.InMemoryStorage;

/**
 * KeyProtectionService class Registers if a password has been entered.
 *
 *@author Max Kolhagen
 */
public class KeyProtectionService extends IntentService {

    //Constants for logging and intent extra
    private static final String TAG = KeyProtectionService.class.getSimpleName();
    private static final String PACKAGE = KeyProtectionService.class.getPackage().getName();

    public static final String ACTION_AUTHENTICATE = PACKAGE + ".action.authenticate";
    public static final String EXTRA_KM_TYPE = PACKAGE + ".extra.keyManagerType";
    public static final String EXTRA_AUTH = PACKAGE + ".extra.auth";

    public KeyProtectionService() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        if (intent == null || !ACTION_AUTHENTICATE.equals(intent.getAction()))
            return;

        KeyManagerPriority.Type type = (KeyManagerPriority.Type) intent.getSerializableExtra(EXTRA_KM_TYPE);

        Log.d(TAG, "onHandleIntent - " + type.name());

        // EXTRA_AUTH: could also be sth else than String!

        switch (type) {
            case SOFTWARE:
            case YUBIKEY:
            case SMARTCARD:
            case SEEK:
            case ANDROID:
                String password = intent.getStringExtra(EXTRA_AUTH);
                InMemoryStorage.getInstance().put(InMemoryStorage.PASSWORD, password);
                break;
            default:
                Log.e(TAG, "Unsupported intent action!");
                return;
        }

        ManagerService.requestManagers(this, null);
    }
}
