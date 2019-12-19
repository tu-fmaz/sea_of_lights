/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package apps.sampleapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import library.WifiP2pServiceConstants;
import primitives.keys.Fingerprint;

import java.util.Map;

/**
 * NeighborBroadcastReceiver class is analogous to the other Neighbor Receiver (cf. core, wifiservice).
 *
 *@author Max Kolhagen
 */
public class NeighborBroadcastReceiver extends BroadcastReceiver {
    private static final String TAG = NeighborBroadcastReceiver.class.getSimpleName();

    public interface NeighborChangedListener {
        void onNeighborsChanged(Map<String, Fingerprint> addresses);
    }

    private final NeighborChangedListener listener;

    public NeighborBroadcastReceiver(final NeighborChangedListener listener) {
        this.listener = listener;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null)
            return;

        Log.v(TAG, "Received broadcast intent!");

        if (!intent.getAction().equals(WifiP2pServiceConstants.ACTION_NEIGHBORS_CHANGED))
            return;

        Log.d(TAG, "Found it!");

        Map<String, Fingerprint> neighbors = (Map) intent.getSerializableExtra(WifiP2pServiceConstants.EXTRA_RESULT_NEIGHBORS);

        for (String address : neighbors.keySet())
            Log.d(TAG, "- " + address + " = " + neighbors.get(address));

        if (this.listener != null)
            this.listener.onNeighborsChanged(neighbors);
    }
}
