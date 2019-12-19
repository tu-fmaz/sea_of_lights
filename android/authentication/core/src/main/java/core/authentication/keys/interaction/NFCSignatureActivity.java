/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.interaction;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import core.authentication.R;
import primitives.keys.Signature;
import primitives.keys.SubKeySignature;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * NFCSignatureActivity class for connecting to NFC security tokens / smart cards for them to sign the queued data.
 *
 *@author Max Kolhagen
 */
public class NFCSignatureActivity extends Activity {
    // Constant for logging
    private static final String TAG = NFCSignatureActivity.class.getSimpleName();

    /**
     * Class for queuing with signature objects that wait to be signed.
     */
    public static class SignatureQueue {

        private static final String FILE = "nfc_queue.dat";

        private static SignatureQueue _instance = null;

        private Queue<Serializable> queue;

        public static SignatureQueue getInstance(Context context) {
            if (_instance == null)
                _instance = new SignatureQueue(context);

            return _instance;
        }

        public SignatureQueue(Context context) {
            try {
                // load from persistent storage
                FileInputStream fis = context.openFileInput(FILE);
                ObjectInputStream ois = new ObjectInputStream(fis);
                this.queue = (Queue) ois.readObject();
                fis.close();
            } catch (Exception e) {
                Log.e(TAG, "Error reading queue!", e);
                this.queue = new ConcurrentLinkedQueue<>();
            }
        }

        /**
         * add signature for master key
         * */
        public void addSignature(Context context, Signature signature) {
            this.queue.add(signature);
            this.save(context);
        }

        /**
         * add signature for sub key
         * */
        public void addSignature(Context context, SubKeySignature signature) {
            this.queue.add(signature);
            this.save(context);
        }

        /**
         * save signature for master and sub- keys
         * */
        private void save(Context context) {
            try {
                // save persistently
                FileOutputStream fos = context.openFileOutput(FILE, Context.MODE_PRIVATE);
                ObjectOutputStream oos = new ObjectOutputStream(fos);
                oos.writeObject(this.queue);
                fos.close();
            } catch (Exception e) {
                Log.e(TAG, "Error saving persistently!", e);
            }
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    // ----

    public static void queueNFCSignature(Context context, Signature signature) {
        SignatureQueue.getInstance(context).addSignature(context, signature);
        showNFCSignatureNotification(context);
    }

    public static void queueNFCSignature(Context context, SubKeySignature signature) {
        SignatureQueue.getInstance(context).addSignature(context, signature);
        showNFCSignatureNotification(context);
    }

    /**
     * Shows progress for saving signature
     * */
    private static void showNFCSignatureNotification(Context context) {
        Intent intent = new Intent(context, NFCSignatureActivity.class);
        PendingIntent pending = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_CANCEL_CURRENT);

        Notification n = new NotificationCompat.Builder(context)
                .setSmallIcon(R.drawable.ic_tap_and_play_black_24dp)
                .setContentIntent(pending)
                .setContentTitle("NFC Hardware Token")
                .setContentText("Interaction required...").build();

        NotificationManager nManager = (NotificationManager) context.getSystemService(NOTIFICATION_SERVICE);
        nManager.notify(11, n);
    }
}
