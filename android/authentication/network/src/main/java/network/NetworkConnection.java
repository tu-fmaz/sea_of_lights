/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package network;

import android.util.Log;

import network.messages.Message;
import primitives.config.Config;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;

/**
 * NetworkConnection class represents a single network socket connection.
 *
 *@author Max Kolhagen
 */
public class NetworkConnection implements Runnable {
    private static final String TAG = NetworkConnection.class.getSimpleName();

    /**
     * Callback interface for incoming messages.
     */
    public interface MessageReceiver {
        void onMessageReceived(String address, Message message);
    }

    /**
     * Fields
     */
    private final MessageReceiver receiver;

    private ServerSocket socket = null;
    private boolean cancel = false;

    /**
     * Constructor.
     *
     * @param port
     * @param receiver
     * @throws IOException
     */
    public NetworkConnection(final int port, MessageReceiver receiver) throws IOException {
        Log.d(TAG, "Starting server");

        this.receiver = receiver;

        // open socket on given port
        this.socket = new ServerSocket(port);

        // start thread for handling incoming connections
        new Thread(this).start();
    }

    @Override
    public void run() {
        while (true) {
            if (this.cancel)
                return;

            try {
                Log.d(TAG, "Waiting for incoming socket connection...");
                Socket client = this.socket.accept();

                String address = client.getInetAddress().getHostAddress();

                Log.d(TAG, "Got incoming socket connection from " + address + ", retrieving message...");
                InputStream input = client.getInputStream();

                // deserialize incoming message
                ObjectInputStream ois = new ObjectInputStream(input);
                Message message = (Message) ois.readObject();
                ois.close();

                input.close();

                if (this.receiver != null)
                    this.receiver.onMessageReceived(address, message);
            } catch (SocketException e) {
                Log.w(TAG, "Error: Socket problem!", e); // Socket closed
            } catch (Exception e) {
                Log.e(TAG, "Error", e);
            }
        }
    }

    public void cancel() {
        Log.d(TAG, "Stopping server!");

        // set cancel flag to true
        this.cancel = true;

        try {
            // close socket
            this.socket.close();
        } catch (IOException e) {
            Log.e(TAG, "Error: Socket problem!", e);
        }
    }

    /**
     * Callback interface for outgoing connections.
     */
    public interface SenderCallback {
        void onSuccess();

        void onFailure(Exception e);
    }

    /**
     * Static method for sending a message to another IP address.
     *
     * @param host
     * @param port
     * @param message
     * @param callback
     */
    public static void sendData(final String host, final int port, final Message message, final SenderCallback callback) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                Log.d(TAG, "Preparing to send, connecting to host: " + host);
                Socket socket = new Socket();

                try {
                    // connect to host:port
                    socket.bind(null);
                    socket.connect((new InetSocketAddress(host, port)), Config.NETWORK_TIMEOUT);

                    Log.d(TAG, "Transmitting message to server...");

                    OutputStream stream = socket.getOutputStream();

                    // write message
                    ObjectOutputStream oos = new ObjectOutputStream(stream);
                    oos.writeObject(message);
                    oos.close();

                    stream.close();

                    Log.d(TAG, "Transmitting done!");

                    if (callback != null)
                        callback.onSuccess();
                } catch (IOException e) {
                    if (callback != null)
                        callback.onFailure(e);
                } finally {
                    // close down socket
                    if (socket == null)
                        return;

                    if (!socket.isConnected())
                        return;

                    try {
                        socket.close();
                    } catch (IOException e) {
                        // swallow
                    }
                }
            }
        }).start();
    }
}

