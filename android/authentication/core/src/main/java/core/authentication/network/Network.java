/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.network;

import android.content.Context;
import android.content.IntentFilter;
import android.util.Log;

import core.authentication.exceptions.NetworkException;
import library.WifiP2pServiceConstants;
import network.NetworkConnection;
import network.messages.Message;
import primitives.config.Config;
import primitives.keys.Fingerprint;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Network class maintains the socket connection for the trust protocol.
 *
 *@author Max Kolhagen
 */
public final class Network implements NetworkConnection.MessageReceiver, AddressBroadcastReceiver.AddressListener {
    private static final String TAG = Network.class.getSimpleName();

    /**
     * Callback listener.
     */
    public interface NetworkListener {
        void onPeerListChanged(Set<Fingerprint> neighbors);

        void onMessageReceived(Fingerprint fingerprint, Message message);
    }

    // Local variables for network communication
    private final NetworkListener listener;
    private final int messageFilter;
    private final AddressBroadcastReceiver addressReceiver;
    private NetworkConnection connection = null;
    private static Map<String, Fingerprint> lastKnownAddresses = null;

    /**
     * CONSTRUCTORS
     */

    public Network(Context context, NetworkListener listener) throws IOException {
        this(context, listener, Message.TYPE_ALL);
    }

    public Network(Context context, NetworkListener listener, int filter) throws IOException {
        Log.d(TAG, "Initializing network...");

        this.listener = listener;
        this.messageFilter = filter;

        // start underlying socket connection
        this.connection = new NetworkConnection(Config.NETWORK_PORT, this);

        // start broadcast receiver
        this.addressReceiver = new AddressBroadcastReceiver(this);
        IntentFilter filters = new IntentFilter();
        filters.addAction(WifiP2pServiceConstants.ACTION_NEIGHBORS_CHANGED);
        context.registerReceiver(this.addressReceiver, filters);
    }

    @Override
    public void onAddressChanged(Map<String, Fingerprint> addresses) {
        Log.d(TAG, "onAddressChanged - " + addresses.size());
        lastKnownAddresses = addresses;

        Set<Fingerprint> result = new HashSet<>();
        for (Fingerprint current : addresses.values())
            result.add(current);

        if (this.listener != null)
            this.listener.onPeerListChanged(result);
    }

    @Override
    public void onMessageReceived(String address, Message message) {
        Log.d(TAG, "onMessageReceived - " + address + ", " + message);

        if (lastKnownAddresses == null || !lastKnownAddresses.containsKey(address)) {
            Log.w(TAG, "- Could not map fingerprint from receiving message");
            return;
        }

        // check message filter
        final int type = message.getType();

        if ((type & this.messageFilter) == 0)
            return;

        Log.d(TAG, "- Passed filter, forwarding...");

        // pass on to listener
        if (this.listener != null)
            this.listener.onMessageReceived(lastKnownAddresses.get(address), message);
    }

    public static void broadcast(final Message message, final NetworkConnection.SenderCallback callback) throws NetworkException {
        if (lastKnownAddresses == null)
            throw new NetworkException("No network information available!");

        Log.d(TAG, "Broadcasting message " + message.getType() + "...");

        for (String address : lastKnownAddresses.keySet()) {
            NetworkConnection.sendData(address, Config.NETWORK_PORT, message, callback);
        }
    }

    /**
     * Sends a message to the given fingerprint.
     *
     * @param fingerprint
     * @param message
     * @param callback
     * @throws NetworkException
     */
    public static void send(final Fingerprint fingerprint, final Message message, final NetworkConnection.SenderCallback callback) throws NetworkException {
        if (lastKnownAddresses == null)
            throw new NetworkException("No network information available!");

        Log.d(TAG, "Sending message " + message.getType() + " to " + fingerprint);

        String address = null;
        for (String current : lastKnownAddresses.keySet()) {
            if (lastKnownAddresses.get(current).equals(fingerprint)) {
                address = current;
                break;
            }
        }

        if (address == null)
            throw new NetworkException("Unable to map fingerprint to an address!");

        NetworkConnection.sendData(address, Config.NETWORK_PORT, message, callback);
    }
}
