/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.network;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import library.WifiP2pServiceConstants;
import primitives.keys.Fingerprint;
import wifi.WifiP2pService;

import java.util.Map;

/**
 * AddressBroadcastReceiver class implements a Receiver for the event that neighbors have changed (cf. NeighborsChangedReceiver).
 *
 *@author Max Kolhagen
 */
public class AddressBroadcastReceiver extends BroadcastReceiver {
    private static final String TAG = AddressBroadcastReceiver.class.getSimpleName();

    // Callback listener
    public interface AddressListener {
        void onAddressChanged(Map<String, Fingerprint> addresses);
    }

    // Local variable for listener
    private final AddressListener listener;

    /**
     * Constructor
     *
     * @param listener
     */
    public AddressBroadcastReceiver(final AddressListener listener) {
        this.listener = listener;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null)
            return;

        Log.v(TAG, "Received broadcast intent!");

        if (!intent.getAction().equals(WifiP2pService.ACTION_NEIGHBORS_CHANGED))
            return;

        Log.d(TAG, "Found it!");

        if (!intent.hasExtra(WifiP2pServiceConstants.EXTRA_RESULT_NEIGHBORS))
            return;

        Map<String, Fingerprint> neighbors = (Map) intent.getSerializableExtra(WifiP2pServiceConstants.EXTRA_RESULT_NEIGHBORS);

        // dispatch to listener
        if (this.listener != null)
            this.listener.onAddressChanged(neighbors);
    }
}
