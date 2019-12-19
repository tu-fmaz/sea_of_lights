/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.interaction;

import android.app.Activity;
import android.content.Intent;
import android.nfc.Tag;
import android.util.Log;

import java.io.IOException;

import nordpol.IsoCard;
import nordpol.android.AndroidCard;
import nordpol.android.OnDiscoveredTagListener;
import nordpol.android.TagDispatcher;

/**
 * NFCActivity class for managing the actual NFC communication.
 *
 *@author Max Kolhagen
 */
public class NFCActivity extends Activity implements OnDiscoveredTagListener {
    private static final String TAG = NFCActivity.class.getSimpleName();

    private TagDispatcher tagDispatcher;

    @Override
    protected void onResume() {
        super.onResume();
        tagDispatcher = TagDispatcher.get(this, this);
        tagDispatcher.enableExclusiveNfc();
    }

    @Override
    public void onPause() {
        super.onPause();
        tagDispatcher.disableExclusiveNfc();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        tagDispatcher.interceptIntent(intent);
    }

    @Override
    public void tagDiscovered(Tag tag) {
        Log.d(TAG, "Reading card...");

        try {
            IsoCard isoCard = AndroidCard.get(tag);

            // check that card is really there
            isoCard.connect();
            isoCard.close();

            Log.d(TAG, "Successfully connected...");
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
