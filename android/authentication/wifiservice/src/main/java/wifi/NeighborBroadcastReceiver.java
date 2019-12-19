/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import primitives.keys.Fingerprint;

import java.util.Map;

/**
 * NeighborBroadcastReceiver class Broadcast receiver for our own Wi-Fi service.
 *
 *@author Max Kolhagen
 */
public class NeighborBroadcastReceiver extends BroadcastReceiver {
    private static final String TAG = NeighborBroadcastReceiver.class.getSimpleName();

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null)
            return;

        Log.v(TAG, "Received broadcast intent!");

        if (!intent.getAction().equals(WifiP2pService.ACTION_NEIGHBORS_CHANGED))
            return;

        Log.d(TAG, "Found it!");

        Map<String, Fingerprint> neighbors = (Map) intent.getSerializableExtra(WifiP2pService.EXTRA_RESULT_NEIGHBORS);

        for (String address : neighbors.keySet())
            Log.d(TAG, "- " + address + " = " + neighbors.get(address));
    }
}
