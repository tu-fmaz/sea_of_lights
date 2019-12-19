/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.interaction;

import android.app.Activity;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import core.authentication.R;
import core.authentication.keys.KeyManagerPriority;
import core.authentication.trust.ManagerService;

/**
 * NFCInitializationActivity class for choosing if a NFC option should be used, and if so - which.
 *
 *@author Max Kolhagen
 */
public class NFCInitializationActivity extends Activity {
    private static final String TAG = NFCInitializationActivity.class.getSimpleName();

    public static final int NOTIFICATION_ID = 0x40;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        this.setContentView(R.layout.activity_nfc);
    }

    @Override
    protected void onResume() {
        super.onResume();

        NotificationManager nManager = (NotificationManager) this.getSystemService(Context.NOTIFICATION_SERVICE);
        nManager.cancel(NOTIFICATION_ID);
    }

    // Functions to manage button-click events

    public void btnSmartcard_Click(View view) {
        Log.d(TAG, "btnSmartcard_Click");

        // remember choice
        SharedPreferences prefs = this.getSharedPreferences(KeyManagerPriority.KEY_MANAGER_PREFS, 0);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(KeyManagerPriority.KEY_MANAGER_TYPE, KeyManagerPriority.Type.SMARTCARD.name());
        editor.commit();

        // re-initialize
        this.reInitialize();
        this.finish();
    }

    public void btnYubiKey_Click(View view) {
        Log.d(TAG, "btnYubiKey_Click");

        // remember choice
        SharedPreferences prefs = this.getSharedPreferences(KeyManagerPriority.KEY_MANAGER_PREFS, 0);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString(KeyManagerPriority.KEY_MANAGER_TYPE, KeyManagerPriority.Type.YUBIKEY.name());
        editor.commit();

        // re-initialize
        this.reInitialize();
        this.finish();
    }

    public void btnNo_Click(View view) {
        Log.d(TAG, "btnNo_Click");

        // remember choice
        SharedPreferences prefs = this.getSharedPreferences(KeyManagerPriority.KEY_MANAGER_PREFS, 0);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putBoolean(KeyManagerPriority.KEY_MANAGER_NFC, false);
        editor.commit();

        // just re-initialize
        this.reInitialize();
        this.finish();
    }

    private void reInitialize() {
        ManagerService.requestManagers(this, null);
    }
}
