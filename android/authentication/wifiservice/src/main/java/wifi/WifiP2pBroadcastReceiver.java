/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.p2p.WifiP2pManager;
import android.util.Log;

/**
 * WifiP2pBroadcastReceiver class Receiver for all Wi-Fi Direct events.
 *
 *@author Max Kolhagen
 */
public class WifiP2pBroadcastReceiver extends BroadcastReceiver {
    private static final String TAG = WifiP2pBroadcastReceiver.class.getSimpleName();

    private static final String[] WIFI_P2P_EVENTS = {
            WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION, WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION,
            WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION, WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION
    };

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();

        // check if is really any of the filtered events (and action is set)
        if (action == null || !this.isEligibleEvent(intent.getAction()))
            return;

        Log.d(TAG, "Received Wifi P2P event, forwarding... " + intent.getAction());

        // simply forward event to our Wifi service
        final Intent forward = new Intent(context, WifiP2pService.class);
        forward.fillIn(intent, 0);
        context.startService(forward);
    }

    private boolean isEligibleEvent(String action) {
        if (action == null)
            return false;

        for (int i = 0; i < WIFI_P2P_EVENTS.length; i++) {
            if (action.equals(WIFI_P2P_EVENTS[i]))
                return true;
        }

        return false;
    }
}
