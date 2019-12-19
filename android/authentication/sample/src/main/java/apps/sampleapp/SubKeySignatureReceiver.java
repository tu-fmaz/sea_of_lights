/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package apps.sampleapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import primitives.keys.KeyID;

/**
 * SubKeySignatureReceiver class receives information about new sub keys (either issued locally, or available for other devices).
 *
 *@author Max Kolhagen
 */
public class SubKeySignatureReceiver extends BroadcastReceiver {
    private static final String TAG = SubKeySignatureReceiver.class.getSimpleName();

    private static final String EXTRA_SUB_KEY_ID = ".extras.SUB_KEY_ID";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(TAG, "New sub key signature was issued.");

        if (intent == null || intent.getAction() == null)
            return;

        if (!intent.hasExtra(EXTRA_SUB_KEY_ID))
            return;

        KeyID keyID = (KeyID) intent.getSerializableExtra(EXTRA_SUB_KEY_ID);

        Log.d(TAG, "- Got KeyID = " + keyID);
    }
}
