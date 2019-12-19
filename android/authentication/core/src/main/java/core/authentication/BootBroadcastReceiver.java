/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import core.authentication.trust.ManagerService;
import core.authentication.trust.TrustProtocolService;
import wifi.WifiP2pService;

/**
 * BootBroadcastReceiver class starts all the services on boot.
 *
 *@author Max Kolhagen
 */
public class BootBroadcastReceiver extends BroadcastReceiver {
    private static final String TAG = BootBroadcastReceiver.class.getSimpleName();

    private static final String[] START_SERVICE_ON_EVENT = {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_USER_PRESENT,
            Intent.ACTION_POWER_CONNECTED, Intent.ACTION_POWER_DISCONNECTED
    };

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null)
            return;

        Log.v(TAG, "onReceive - " + intent);

        // check if it is really any of the registered events
        if (!this.isEligibleEvent(intent.getAction()))
            return;

        // start all services
        WifiP2pService.startService(context);
        ManagerService.requestManagers(context, null);
        context.startService(new Intent(context, AuthenticationService.class));
        context.startService(new Intent(context, TrustProtocolService.class));
    }

    private boolean isEligibleEvent(String action) {
        if (action == null)
            return false;

        for (int i = 0; i < START_SERVICE_ON_EVENT.length; i++) {
            if (action.equals(START_SERVICE_ON_EVENT[i]))
                return true;
        }

        return false;
    }
}
