/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi;

import android.net.wifi.p2p.WifiP2pDevice;

/**
 * WifiP2pUtils class gets the current device status
 *
 *@author Max Kolhagen
 */
public final class WifiP2pUtils {
    private WifiP2pUtils() {
        // hide
    }

    /**
     * Get the string representation of a device status.
     *
     * @param deviceStatus
     * @return
     */
    public static String getDeviceStatus(int deviceStatus) {
        switch (deviceStatus) {
            case WifiP2pDevice.CONNECTED:
                return "Connected";
            case WifiP2pDevice.INVITED:
                return "Invited";
            case WifiP2pDevice.FAILED:
                return "Failed";
            case WifiP2pDevice.AVAILABLE:
                return "Available";
            case WifiP2pDevice.UNAVAILABLE:
                return "Unavailable";
            default:
                return "Unknown";
        }
    }
}
