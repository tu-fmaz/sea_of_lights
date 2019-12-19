
/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import core.authentication.R;
import core.authentication.exceptions.KeyManagerException;
import core.authentication.keys.interaction.NFCInitializationActivity;
import core.authentication.keys.modules.AndroidKeyManager;
import core.authentication.keys.modules.SeekKeyManager;
import core.authentication.keys.modules.SmartcardKeyManager;
import core.authentication.keys.modules.SoftwareKeyManager;
import core.authentication.keys.modules.TestKeyManager;
import core.authentication.keys.modules.YubiKeyManager;
import primitives.config.Config;
import primitives.keys.SignatureParameter;

/**
 * KeyManagerPriority class enforces a certain priority when it comes to the different key managers.
 * Current the hardware-based key manager are prioritized, if there is not a suitable solution,
 * a software-based solution is selected.
 *
 *@author Max Kolhagen
 */
public class KeyManagerPriority {

    // Constant for logging
    private static final String TAG = KeyManagerPriority.class.getSimpleName();

    // Constants for shared preferences
    public static final String KEY_MANAGER_PREFS = "keyManagerPreferences";
    public static final String KEY_MANAGER_TYPE = "keyManagerType";
    public static final String KEY_MANAGER_NFC = "keyManagerNFC";

    // Different types of key managers.
    public enum Type {
        TEST,
        SOFTWARE,
        ANDROID,
        SEEK,
        SMARTCARD,
        YUBIKEY;
    }

    /**
     * Returns the prioritized key manager.
     *
     * @param context
     * @param basePath
     * @return
     * @throws Exception
     */
    public static KeyManager getPriorityKeyManager(final Context context,
                                                   final String basePath) throws Exception {
        final Type type = KeyManagerPriority.getPreferredKeyManager(context);

        if (type == null)
            return null;

        Log.d(TAG, "Selected method: " + type.name());

        KeyManager manager = null;
        try {
            switch (type) {
                case TEST:
                    manager = new TestKeyManager(context, basePath);
                    break;
                case SOFTWARE:
                    manager = new SoftwareKeyManager(context, basePath);
                    break;
                case ANDROID:
                    manager = new AndroidKeyManager(context, basePath);
                    break;
                case SEEK:
                    manager = new SeekKeyManager(context, basePath);
                    break;
                case SMARTCARD:
                    manager = new SmartcardKeyManager(context, basePath);
                    break;
                case YUBIKEY:
                    manager = new YubiKeyManager(context, basePath);
                    break;
                default:
                    throw new IllegalStateException("Unknown KeyManager type: " + type);
            }
        } catch (KeyManagerException e) {
            Log.e(TAG, "Missing information, Key Manager should have taken care of!", e);
            return null;
        }

        // stores the choice in the shared preferences
        SharedPreferences prefs = context.getSharedPreferences(KEY_MANAGER_PREFS, 0);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(KEY_MANAGER_TYPE, type.name());
        editor.commit();

        return manager;
    }

    private static Type getPreferredKeyManager(Context context) {
        boolean useNFCMethod = true;
        try {
            // check if NFC has been disabled, or get previous choice from share preferences
            SharedPreferences prefs = context.getSharedPreferences(KEY_MANAGER_PREFS, 0);
            useNFCMethod = prefs.getBoolean(KEY_MANAGER_NFC, true);
            return Type.valueOf(prefs.getString(KEY_MANAGER_TYPE, null));
        } catch (Exception e) {
            Log.w(TAG, "Unable to read key store type file");
        }

        // check if seek is available
        //if (SeekKeyManager.isSeekAvailable(context))
          //  return Type.SEEK;

        // initialize NFC if chosen
        if (useNFCMethod) {
            Intent intent = new Intent(context, NFCInitializationActivity.class);
            PendingIntent pending = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);

            Notification n = new NotificationCompat.Builder(context)
                    .setSmallIcon(R.drawable.ic_tap_and_play_black_24dp)
                    .setContentIntent(pending)
                    .setContentTitle("Action Required!")
                    .setContentText("Please select your desired key store format...").build();

            NotificationManager nManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            nManager.notify(NFCInitializationActivity.NOTIFICATION_ID, n);
            return null;
        }

        // before JB use software-only
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2)
            return Type.SOFTWARE;

        // for ECDSA even with KK
        if (Config.KEY_SIGNATURE_PARAMETERS == SignatureParameter.ECDSA &&
                Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT)
            return Type.SOFTWARE;

        // otherwise Android
        return Type.ANDROID;
    }
}
