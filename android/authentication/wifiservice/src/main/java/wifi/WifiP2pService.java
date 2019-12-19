/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi;

import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.net.NetworkInfo;
import android.net.wifi.WpsInfo;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pDeviceList;
import android.net.wifi.p2p.WifiP2pInfo;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.IBinder;
import android.support.annotation.Nullable;
import android.util.Log;

import primitives.keys.Fingerprint;

import java.io.Serializable;
import java.util.Map;

/**
 * WifiP2pService class manages the Wi-Fi Direct connections and performs the
 * bootstrapping protocol.
 *
 *@author Max Kolhagen
 */
public class WifiP2pService extends Service implements WifiP2pManager.ChannelListener,
        WifiP2pManager.PeerListListener, WifiP2pManager.ConnectionInfoListener,
        WifiP2pProtocol.OnAddressesChangeListener {
    private static final String TAG = WifiP2pService.class.getSimpleName();
    private static final String PACKAGE = WifiP2pService.class.getPackage().getName();

    public static final String ACTION_UPDATE = PACKAGE + ".action.UPDATE";
    public static final String ACTION_DISCOVER = PACKAGE + ".action.DISCOVER";
    public static final String ACTION_GET_INFO = PACKAGE + ".action.GET_INFO";
    public static final String ACTION_GET_NEIGHBORS = PACKAGE + ".action.GET_NEIGHBORS";
    public static final String ACTION_TRIGGER_BROADCAST = PACKAGE + ".action.TRIGGER_BROADCAST";
    public static final String ACTION_NEIGHBORS_CHANGED = PACKAGE + ".action.NEIGHBORS_CHANGED";

    public static final String EXTRA_RESULT = PACKAGE + ".extra.RESULT";
    public static final String EXTRA_RESULT_INFO = PACKAGE + ".extra.RESULT_INFO";
    public static final String EXTRA_RESULT_INFO_FP = PACKAGE + ".extra.INFO_FP";
    public static final String EXTRA_RESULT_NEIGHBORS = PACKAGE + ".extra.RESULT_NEIGHBORS";

    private static final int RESPONSE_CODE_INFO_SUCCESS = 0x11;
    private static final int RESPONSE_CODE_INFO_NOT_AVAILABLE = 0x12;
    private static final int RESPONSE_CODE_NEIGHBORS_SUCCESS = 0x21;
    private static final int RESPONSE_CODE_NEIGHBORS_EMPTY = 0x22;

    /**
     * Wifi P2P
     */
    private WifiP2pManager manager = null;
    private WifiP2pManager.Channel channel = null;
    private WifiP2pProtocol protocol = null;

    @Override
    public void onCreate() {
        Log.d(TAG, "(SERVICE) onCreate");
        super.onCreate();

        // instantiate Wi-Fi components and protocol
        this.manager = (WifiP2pManager) this.getSystemService(Context.WIFI_P2P_SERVICE);
        this.channel = this.manager.initialize(this, this.getMainLooper(), this);
        this.protocol = new WifiP2pProtocol(this);

        // trigger discovery and request connection information
        this.performDiscovery();
        this.manager.requestConnectionInfo(this.channel, this);
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "(SERVICE) onBind");
        return null;
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "(SERVICE) onDestroy");
        super.onDestroy();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "(SERVICE) onStartCommand");
        super.onStartCommand(intent, flags, startId);

        // dispatch respective action
        try {
            if (intent != null && intent.getAction() != null) {
                if (intent.getAction().equals(ACTION_UPDATE)) {
                    this.performUpdate();

                } else if (intent.getAction().equals(ACTION_DISCOVER)) {
                    this.performDiscovery();

                } else if (intent.getAction().equals(ACTION_GET_INFO)) {
                    PendingIntent result = intent.getParcelableExtra(EXTRA_RESULT);

                    Fingerprint fingerprint = intent.getParcelableExtra(EXTRA_RESULT_INFO_FP);

                    this.getInformation(fingerprint, result);

                } else if (intent.getAction().equals(ACTION_GET_NEIGHBORS)) {
                    PendingIntent result = intent.getParcelableExtra(EXTRA_RESULT);

                    this.getNeighbors(result);

                } else if (intent.getAction().equals(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)) {
                    int state = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, -1);

                    this.receivedWifiP2pStateChanged(state);

                } else if (intent.getAction().equals(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)) {
                    this.receivedWifiP2pPeersChanged();

                } else if (intent.getAction().equals(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)) {
                    NetworkInfo networkInfo = intent
                            .getParcelableExtra(WifiP2pManager.EXTRA_NETWORK_INFO);

                    this.receivedWifiP2pConnectionChanged(networkInfo);

                } else if (intent.getAction().equals(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)) {
                    WifiP2pDevice device = intent.getParcelableExtra(
                            WifiP2pManager.EXTRA_WIFI_P2P_DEVICE);

                    this.receivedWifiP2pThisDeviceChanged(device);

                } else if (intent.getAction().equals(ACTION_TRIGGER_BROADCAST)) {
                    this.onAddressesChanged(this.protocol.getCurrentAddresses());

                } else {
                    Log.w(TAG, "(SERVICE) - Received an unknown action: " + intent.getAction());

                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Unable to handle Intent!", e);
        }

        // to keep activated
        return START_STICKY;
    }

    // ---- ACTIONS

    /**
     * Performs an update of the fingerprint and IP address mapping.
     */
    private void performUpdate() {
        this.protocol.triggerUpdate();
    }

    /**
     * Triggers a discovery on the Wi-Fi channel.
     */
    private void performDiscovery() {
        Log.d(TAG, "(ACTION) performDiscovery");

        this.manager.discoverPeers(this.channel, new WifiP2pManager.ActionListener() {
            @Override
            public void onSuccess() {
                // Will issue WIFI_P2P_PEERS_CHANGED_ACTION broadcast -> receivedWifiP2pPeersChanged()
                Log.d(TAG, "(ACTION) - discoverPeers - Success, Waiting for receivedWifiP2pPeersChanged()");
            }

            @Override
            public void onFailure(int reasonCode) {
                // The reason for failure could be one of P2P_UNSUPPORTED, ERROR or BUSY
                Log.e(TAG, "(ACTION) - discoverPeers - Failure! " + reasonCode);
            }
        });
    }

    /**
     * Retrieves information about a single peer.
     *
     * @param fingerprint
     * @param result
     */
    private void getInformation(Fingerprint fingerprint, PendingIntent result) {
        Log.d(TAG, "(ACTION) getInformation: " + result);

        String address = null;
        for (String current : this.protocol.getCurrentAddresses().keySet()) {
            if (!this.protocol.getCurrentAddresses().get(current).equals(fingerprint))
                continue;

            address = current;
            break;
        }

        try {
            // send response intent
            Intent intent = new Intent();
            int rc = RESPONSE_CODE_INFO_NOT_AVAILABLE;
            if (address != null) {
                rc = RESPONSE_CODE_INFO_SUCCESS;
                intent.putExtra(EXTRA_RESULT_INFO, address);
            }
            result.send(this, rc, intent);
        } catch (Exception e) {
            Log.e(TAG, "(ACTION) - Unable to respond to application!", e);
        }
    }

    /**
     * Retrieves the information about all current neighbors.
     *
     * @param result
     */
    private void getNeighbors(PendingIntent result) {
        Log.d(TAG, "(ACTION) getNeighbors: " + result);

        try {
            // fill & send result
            Intent data = new Intent();
            Map<String, Fingerprint> neighbors = this.protocol.getCurrentAddresses();
            data.putExtra(EXTRA_RESULT_NEIGHBORS, (Serializable) neighbors);
            int rc = RESPONSE_CODE_NEIGHBORS_SUCCESS;
            if (neighbors.size() == 0)
                rc = RESPONSE_CODE_NEIGHBORS_EMPTY;
            result.send(this, rc, data);
        } catch (Exception e) {
            Log.e(TAG, "(ACTION) - Unable to respond to application!", e);
        }
    }

    // ---- METHODS

    @Override
    public void onAddressesChanged(Map<String, Fingerprint> addresses) {
        // send broadcast that neighbors have changed
        Intent intent = new Intent(WifiP2pService.ACTION_NEIGHBORS_CHANGED);
        intent.putExtra(EXTRA_RESULT_NEIGHBORS, (Serializable) addresses);
        this.sendBroadcast(intent);
    }

    /**
     * Enables/Disables the protocol connection.
     *
     * @param enabled
     * @return
     */
    private boolean setProtocolEnabled(boolean enabled) {
        try {
            this.protocol.setEnabled(enabled);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Could not trigger protocol!", e);
            return false;
        }
    }

    // ---- WIFI DIRECT CHANNEL / CALLBACKS

    @Override
    public void onChannelDisconnected() {
        Log.w(TAG, "(ACTION) - onChannelDisconnected");

        this.setProtocolEnabled(false);
    }

    @Override
    public void onPeersAvailable(WifiP2pDeviceList peers) {
        Log.d(TAG, "(WIFI) onPeersAvailable - Size: " + peers.getDeviceList().size());

        // just for debugging (not actually needed)
        for (WifiP2pDevice device : peers.getDeviceList()) {
            Log.d(TAG, "(WIFI) - " + device);
        }
    }

    @Override
    public void onConnectionInfoAvailable(WifiP2pInfo info) {
        Log.d(TAG, "(WIFI) onConnectionInfoAvailable: " + info);

        try {
            // inform the protocol
            this.protocol.updateConnectionInfo(info);
        } catch (Exception e) {
            Log.e(TAG, "Unable to update connection info!", e);
        }
    }

    // ---- WIFI DIRECT BROADCASTS

    public void receivedWifiP2pStateChanged(int state) {
        Log.d(TAG, "(WIFI) receivedWifiP2pStateChanged: " + state);

        boolean enabled = (state == WifiP2pManager.WIFI_P2P_STATE_ENABLED);

        // trigger the protocol connection
        this.setProtocolEnabled(enabled);

        if (enabled)
            this.performDiscovery();
    }

    public void receivedWifiP2pPeersChanged() {
        Log.d(TAG, "(WIFI) receivedWifiP2pPeersChanged - Requesting peers, Waiting for onPeersAvailable()");

        // this will call onPeersAvailable()
        this.manager.requestPeers(this.channel, this);
    }

    public void receivedWifiP2pConnectionChanged(NetworkInfo info) {
        Log.d(TAG, "(WIFI) receivedWifiP2pConnectionChanged: " + info);

        if (!info.isConnected()) {
            this.setProtocolEnabled(false);
            return;
        }

        // got new connection, request information
        this.manager.requestConnectionInfo(this.channel, this);
    }

    public void receivedWifiP2pThisDeviceChanged(WifiP2pDevice device) {
        // called when my own device changes
        Log.d(TAG, "(WIFI) receivedWifiP2pThisDeviceChanged: " + device);
    }

    // ----

    /**
     * Public wrapper method for starting the service.
     *
     * @param context
     */
    public static void startService(Context context) {
        Log.v(TAG, "(SERVICE) Starting Wifi P2P Service...");
        context.startService(new Intent(context, WifiP2pService.class));
    }

    // ---- DELETE? MAYBE USE LATER FOR (AUTO) CONNECT

    private void connect(WifiP2pDevice device) {
        Log.d(TAG, "connect: " + device.deviceName);

        WifiP2pConfig config = new WifiP2pConfig();
        config.deviceAddress = device.deviceAddress;
        config.wps.setup = WpsInfo.PBC;
        this.manager.connect(this.channel, config, new WifiP2pManager.ActionListener() {
            @Override
            public void onSuccess() {
                Log.d(TAG, "onConnectClick - Success, Waiting for receivedWifiP2pConnectionChanged()");
            }

            @Override
            public void onFailure(int reason) {
                Log.e(TAG, "onConnectClick - Failure: " + reason);
            }
        });
    }

    private void disconnect(final WifiP2pDevice device) {
        Log.d(TAG, "disconnect: " + device.deviceName);

        this.manager.removeGroup(this.channel, new WifiP2pManager.ActionListener() {
            @Override
            public void onSuccess() {
                Log.d(TAG, "onDisconnectClick - Success");
            }

            @Override
            public void onFailure(int reason) {
                Log.d(TAG, "onDisconnectClick - Failure: " + reason);
            }
        });
    }
}
