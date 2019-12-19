/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * BootBroadcastReceiver class implements a classical boot Broadcast-Receiver.
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

        Log.v(TAG, "Received broadcast intent: " + intent);

        // check if this is really any of the filtered events.
        if (!this.isEligibleEvent(intent.getAction()))
            return;

        // start the service
        WifiP2pService.startService(context);
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
