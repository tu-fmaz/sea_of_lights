/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi;

import android.net.wifi.p2p.WifiP2pInfo;
import android.util.Log;

import network.NetworkConnection;
import network.messages.Message;
import primitives.config.Config;
import primitives.helper.InMemoryStorage;
import primitives.keys.Fingerprint;
import wifi.network.messages.AddressMessage;
import wifi.network.messages.FingerprintMessage;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * WifiP2pProtocol class implements the actual bootstrapping protocol
 *
 *@author Max Kolhagen
 */
public class WifiP2pProtocol implements NetworkConnection.MessageReceiver {
    private static final String TAG = WifiP2pProtocol.class.getSimpleName();

    /**
     * Callback interface, for when new information is available.
     */
    public interface OnAddressesChangeListener {
        void onAddressesChanged(Map<String, Fingerprint> addresses);
    }

    /**
     *
     */
    private final OnAddressesChangeListener listener;
    private final InMemoryStorage memory;

    private WifiP2pInfo info = null;
    private NetworkConnection connection = null;
    private Map<String, Fingerprint> addresses = new HashMap<>();


    /**
     * Constructor.
     */
    public WifiP2pProtocol(OnAddressesChangeListener listener) {
        //this.addresses = new HashMap<>();
        this.listener = listener;
        this.memory = InMemoryStorage.getInstance();
    }

    /**
     * Getter & Setter
     */
    public Map<String, Fingerprint> getCurrentAddresses() {
        return this.addresses;
    }

    /**
     * Resumes/Suspends the current socket connection.
     *
     * @param enabled
     * @throws IOException
     */
    public void setEnabled(boolean enabled) throws IOException {
        Log.d(TAG, "(PROTOCOL) setEnabled - " + enabled);

        if (enabled) {
            this.connection = new NetworkConnection(Config.NETWORK_WIFI_PORT, this);
            return;
        }

        Log.d(TAG, "(PROTOCOL) Clearing addresses and cancelling connection!");

        // clear all peer information
        this.addresses.clear();
        if (this.listener != null)
            this.listener.onAddressesChanged(this.addresses);

        // cancel the connection if available
        if (this.connection == null)
            return;

        this.connection.cancel();
        this.connection = null;
    }

    /**
     * Called when a new information about the network is available
     *
     * @param info
     * @throws Exception
     */
    public void updateConnectionInfo(WifiP2pInfo info) throws Exception {
        Log.d(TAG, "(PROTOCOL) updateConnectionInfo - " + info);

        this.info = info;

        // check if valid
        if (info == null || info.groupOwnerAddress == null) {
            this.setEnabled(false);
            return;
        }

        // start the connection
        if (this.connection == null)
            this.setEnabled(true);

        // if GO, just wait for incoming connections
        if (!this.info.isGroupOwner)
            this.sendFingerprintToGroupOwner();
        else
            this.propagateInformation();
    }

    /**
     * Trigger the update of the fingerprint.
     */
    public void triggerUpdate() {
        Log.d(TAG, "(PROTOCOL) triggerUpdate");

        if (this.info == null || this.info.groupOwnerAddress == null)
            return;

        if (!this.info.isGroupOwner)
            this.sendFingerprintToGroupOwner();
    }

    /**
     * Clients: send fingerprint information to the group owner.
     */
    private void sendFingerprintToGroupOwner() {
        // TODO: retry for x secs?
        Log.d(TAG, "Sending fingerprint message to group owner...");

        // otherwise send address message
        final String address = this.info.groupOwnerAddress.getHostAddress();

        // check if the fingerprint is available
        Fingerprint fingerprint = (Fingerprint) this.memory.get(InMemoryStorage.FINGERPRINT);
        if (fingerprint == null) {
            Log.w(TAG, "Fingerprint is still null!");
            return;
        }

        // connect to the group owner, in order for him to acquire our IP address
        NetworkConnection.sendData(address, Config.NETWORK_WIFI_PORT, new FingerprintMessage(fingerprint), new NetworkConnection.SenderCallback() {
            @Override
            public void onSuccess() {
                Log.d(TAG, "- Success");
            }

            @Override
            public void onFailure(Exception e) {
                Log.e(TAG, "- Error: Could not send message!", e);
            }
        });
    }

    /**
     * GROUP OWNER: send all gathered information to all clients
     */
    private void propagateInformation() {
        Log.d(TAG, "Propagating information...");

        // check if local fingerprint is available
        Fingerprint fingerprint = (Fingerprint) this.memory.get(InMemoryStorage.FINGERPRINT);
        if (fingerprint == null) {
            Log.w(TAG, "Fingerprint is still null!");
            return;
        }

        // iterate over available clients
        final Iterator<Map.Entry<String, Fingerprint>> iterator = this.addresses.entrySet().iterator();
        while (iterator.hasNext()) {
            final Map.Entry<String, Fingerprint> entry = iterator.next();

            final String address = entry.getKey();

            Log.d(TAG, "- " + address);
            Log.d(TAG, "- Send my own fingerprint...");

            // send my own key (as group owner)
            NetworkConnection.sendData(address, Config.NETWORK_WIFI_PORT, new FingerprintMessage(fingerprint), new NetworkConnection.SenderCallback() {
                @Override
                public void onSuccess() {
                    Log.d(TAG, "- Success");
                }

                @Override
                public void onFailure(Exception e) {
                    Log.e(TAG, "- Error: Could not send message!", e);

                    // remove connection on failure
                    iterator.remove();
                    if (listener != null)
                        listener.onAddressesChanged(addresses);
                }
            });

            Log.d(TAG, "- Send all others...");

            // send address information about other clients
            final Iterator<Map.Entry<String, Fingerprint>> nestedIterator = this.addresses.entrySet().iterator();
            while (nestedIterator.hasNext()) {
                final Map.Entry<String, Fingerprint> nestedEntry = nestedIterator.next();

                final String nestedAddress = nestedEntry.getKey();

                // do not send their own fingerprint
                if (nestedAddress.equals(address))
                    continue;

                NetworkConnection.sendData(address, Config.NETWORK_WIFI_PORT, new AddressMessage(nestedAddress, nestedEntry.getValue()), new NetworkConnection.SenderCallback() {
                    @Override
                    public void onSuccess() {
                        Log.d(TAG, "- Success");
                    }

                    @Override
                    public void onFailure(Exception e) {
                        Log.e(TAG, "- Error: Could not send message!", e);

                        // remove connection on failure
                        nestedIterator.remove();
                        if (listener != null)
                            listener.onAddressesChanged(addresses);
                    }
                });
            }
        }
    }

    @Override
    public void onMessageReceived(String address, Message message) {
        Log.d(TAG, "onMessageReceived - " + address + ", type: " + message.getType());

        // distinguish message type
        if (AddressMessage.TYPE_ADDRESS == message.getType()) {
            Log.d(TAG, "Received AddressMessage");

            if (this.info.isGroupOwner) {
                Log.w(TAG, "Should not be GO here!");
                return;
            }

            AddressMessage am = (AddressMessage) message;

            // update information
            this.addresses.put(am.getAddress(), am.getFingerprint());
            if (listener != null)
                listener.onAddressesChanged(addresses);

            //if (!this.info.isGroupOwner)
            //    this.sendFingerprintToGroupOwner();

        } else if (FingerprintMessage.TYPE_FINGERPRINT == message.getType()) {
            Log.d(TAG, "Received FingerprintMessage");

            // received as group owner
            FingerprintMessage fm = (FingerprintMessage) message;

            // update information
            this.addresses.put(address, fm.getFingerprint());
            if (listener != null)
                listener.onAddressesChanged(addresses);

            if (this.info.isGroupOwner)
                this.propagateInformation();
        }
    }
}
