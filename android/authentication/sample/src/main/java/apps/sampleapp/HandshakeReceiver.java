/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package apps.sampleapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * HandshakeReceiver class receives events when a handshake was successfully performed by the local device.
 *
 *@author Max Kolhagen
 */
public class HandshakeReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(HandshakeReceiver.class.getSimpleName(), "Got handshake - " + intent);
    }
}
