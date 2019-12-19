/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package library;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

import primitives.keys.Fingerprint;

/**
 * WifiP2pServiceConstants class provides a simpler interface for interacting with the Wifi Direct service.
 *
 *@author Max Kolhagen
 */
public final class WifiP2pServiceConstants {
    private WifiP2pServiceConstants() {
        // hide
    }

    public static final String APPLICATION_NAME = "core.authentication";
    public static final String PACKAGE_NAME = "wifi";
    public static final String SERVICE_NAME = PACKAGE_NAME + ".WifiP2pService";

    public static final String ACTION_UPDATE = PACKAGE_NAME + ".action.UPDATE";
    public static final String ACTION_DISCOVER = PACKAGE_NAME + ".action.DISCOVER";
    public static final String ACTION_GET_INFO = PACKAGE_NAME + ".action.GET_INFO";
    public static final String ACTION_GET_NEIGHBORS = PACKAGE_NAME + ".action.GET_NEIGHBORS";
    public static final String ACTION_TRIGGER_BROADCAST = PACKAGE_NAME + ".action.TRIGGER_BROADCAST";
    public static final String ACTION_NEIGHBORS_CHANGED = PACKAGE_NAME + ".action.NEIGHBORS_CHANGED";

    public static final String EXTRA_RESULT = PACKAGE_NAME + ".extra.RESULT";
    public static final String EXTRA_RESULT_INFO = PACKAGE_NAME + ".extra.RESULT_INFO";
    public static final String EXTRA_RESULT_INFO_FP = PACKAGE_NAME + ".extra.INFO_FP";
    public static final String EXTRA_RESULT_NEIGHBORS = PACKAGE_NAME + ".extra.RESULT_NEIGHBORS";

    public static final int RESPONSE_CODE_INFO_SUCCESS = 0x11;
    public static final int RESPONSE_CODE_INFO_NOT_AVAILABLE = 0x12;
    public static final int RESPONSE_CODE_NEIGHBORS_SUCCESS = 0x21;
    public static final int RESPONSE_CODE_NEIGHBORS_EMPTY = 0x22;

    public static void startService(final Context context) {
        Intent intent = new Intent();
        intent.setClassName(APPLICATION_NAME, SERVICE_NAME);
        context.startService(intent);
    }

    public static void startDiscovery(final Context context) {
        Intent intent = new Intent();
        intent.setClassName(APPLICATION_NAME, SERVICE_NAME);
        intent.setAction(ACTION_DISCOVER);
        context.startService(intent);
    }

    public static void requestInformation(final Context context, Fingerprint fingerprint, PendingIntent result) {
        Intent intent = new Intent();
        intent.setClassName(APPLICATION_NAME, SERVICE_NAME);
        intent.setAction(ACTION_GET_INFO);
        intent.putExtra(EXTRA_RESULT_INFO_FP, fingerprint);
        intent.putExtra(EXTRA_RESULT, result);
        context.startService(intent);
    }

    // Map<String, Fingerprint>
    public static void getCurrentNeighbors(final Context context, PendingIntent result) {
        Intent intent = new Intent();
        intent.setClassName(APPLICATION_NAME, SERVICE_NAME);
        intent.setAction(ACTION_GET_NEIGHBORS);
        intent.putExtra(EXTRA_RESULT, result);
        context.startService(intent);
    }

    // new FP/addr, exchange, wait for broadcast...
    public static void triggerUpdate(final Context context) {
        Intent intent = new Intent();
        intent.setClassName(APPLICATION_NAME, SERVICE_NAME);
        intent.setAction(ACTION_UPDATE);
        context.startService(intent);
    }

    public static void triggerBroadcast(final Context context) {
        Intent intent = new Intent();
        intent.setClassName(APPLICATION_NAME, SERVICE_NAME);
        intent.setAction(ACTION_TRIGGER_BROADCAST);
        context.startService(intent);
    }
}
