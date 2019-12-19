
/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package apps.sampleapp;

import android.app.Activity;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.RemoteException;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.Toast;

import library.Authentication;
import library.AuthenticationService;
import library.WifiP2pServiceConstants;
import primitives.keys.Fingerprint;
import primitives.keys.KeyID;
import primitives.trust.MetaInformation;
import primitives.trust.TrustInfo;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * MainActivity class Sample application for demonstrating all functionalities of the authentication service.
 *
 *@author Max Kolhagen
 */
public class MainActivity extends Activity implements NeighborBroadcastReceiver.NeighborChangedListener, AdapterView.OnItemSelectedListener {
    private static final String TAG = MainActivity.class.getSimpleName();

    /**
     * FIELDS
     */
    private ArrayAdapter<Fingerprint> data = null;
    private Spinner spnPerson = null;

    private AuthenticationService authentication = null;
    private NeighborBroadcastReceiver neighborReceiver = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.setContentView(R.layout.activity_main);

        this.spnPerson = (Spinner) this.findViewById(R.id.spinner_person);
        this.spnPerson.setOnItemSelectedListener(this);

        // instantiate neighbor broadcast receiver
        this.neighborReceiver = new NeighborBroadcastReceiver(this);
    }

    @Override
    public void onNeighborsChanged(Map<String, Fingerprint> addresses) {
        // update neighbors displayed in the spinner
        Log.d(TAG, "NEIGHBORS!" + addresses.size());
        List<Fingerprint> spinnerArray = new ArrayList<>();
        spinnerArray.addAll(addresses.values());

        this.data = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, spinnerArray);

        this.data.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        this.spnPerson.setAdapter(this.data);
    }

    @Override
    protected void onResume() {
        super.onResume();

        // resume the broadcast receiver
        IntentFilter filters = new IntentFilter();
        filters.addAction(WifiP2pServiceConstants.ACTION_NEIGHBORS_CHANGED);
        this.registerReceiver(this.neighborReceiver, filters);

        // trigger discovery for Wi-Fi
        WifiP2pServiceConstants.startDiscovery(this);

        Log.d(TAG, "Checking if authentication service is installed: " + Authentication.isInstalled(this));
        Log.d(TAG, "Checking if authentication service is available: " + Authentication.isAvailable());

        // check if the authentication service is available
        if (!Authentication.isAvailable())
            this.requestAuthenticationService();
    }

    @Override
    protected void onPause() {
        super.onPause();

        // suspend the broadcast receiver
        this.unregisterReceiver(this.neighborReceiver);
    }

    @Override
    public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
        // only for debugging
        Log.d(TAG, "onItemSelected - " + position);
        Log.d(TAG, this.data.getItem(position).toString());
    }

    @Override
    public void onNothingSelected(AdapterView<?> parent) {
        // only for debugging
        Log.d(TAG, "onNothingSelected");
    }

    /**
     * Requests the authentication service through the library.
     */
    private void requestAuthenticationService() {
        Log.d(TAG, "Requesting authentication service...");
        boolean result = Authentication.request(this, new Authentication.ServiceReceiver() {
            @Override
            public void onAuthenticationServiceReceived(AuthenticationService service) {
                Log.d(TAG, "Received service!");
                MainActivity.this.authentication = service;
            }

            @Override
            public void onAuthenticationServiceFailure(Exception e) {
                Log.e(TAG, "Unable to connect to authentication service! Is it installed?");
            }
        });

        if (!result)
            Toast.makeText(this, "The AuthenticationService could not be requested!", Toast.LENGTH_LONG).show();
    }

    /**
     * Get the selected fingerprint (if authentication service is available).
     *
     * @return Fingerprint
     */
    private Fingerprint getSelectedFingerprint() {
        if (this.authentication == null) {
            Toast.makeText(this, "Auth not available", Toast.LENGTH_SHORT).show();
            return null;
        }

        if (this.spnPerson.getSelectedItem() == null) {
            Toast.makeText(this, "Nothing selected", Toast.LENGTH_SHORT).show();
            return null;
        }

        return (Fingerprint) this.spnPerson.getSelectedItem();
    }

    /**
     * BUTTON CLICK HANDLER
     */
    public void btnHandshake_Click(View view) {
        Fingerprint selected = this.getSelectedFingerprint();
        if (selected == null)
            return;

        try {
            Log.d(TAG, "Trying to perform handshake!");
            boolean result = this.authentication.performHandshake(selected);
            Log.d(TAG, "- Result: " + result);
        } catch (RemoteException e) {
            Log.e(TAG, "Error", e);
        }
    }

    public void btnTrustInfo_Click(View view) {
        Fingerprint selected = this.getSelectedFingerprint();
        if (selected == null)
            return;

        try {
            Log.d(TAG, "Trying to get trust info!");
            TrustInfo info = this.authentication.getTrustInfo(selected);
            Log.d(TAG, info.toString());
        } catch (RemoteException e) {
            Log.e(TAG, "Error", e);
        }
    }

    public void btnMeta_Click(View view) {
        Fingerprint selected = this.getSelectedFingerprint();
        if (selected == null)
            return;


        try {
            Log.d(TAG, "Trying to get meta!");
            MetaInformation info = this.authentication.getMetaInformation(selected);

            if(null != info)
                Log.d(TAG, "" + info.get(MetaInformation.META_LAST_SYNC));

        } catch (RemoteException e) {
            Log.e(TAG, "Error", e);
        }
    }

    public void btnWifiDiscovery_Click(View view) {
        Log.d(TAG, "btnWifiDiscovery_Click");
        WifiP2pServiceConstants.startDiscovery(this);
    }

    public void btnWifiUpdate_Click(View view) {
        Log.d(TAG, "btnWifiUpdate_Click");
        WifiP2pServiceConstants.triggerUpdate(this);
    }

    public void btnWifiStart_Click(View view) {
        Log.d(TAG, "btnWifiStart_Click");
        //WifiP2pServiceConstants.getCurrentNeighbors(this, pending);
        WifiP2pServiceConstants.startService(this);
    }

    public void btnWifiManual_Click(View view) {
        Log.d(TAG, "btnWifiManual_Click");
        //WifiP2pServiceConstants.getCurrentNeighbors(this, pending);
        WifiP2pServiceConstants.triggerBroadcast(this);
    }

    public void btnAvailableSubKeys_Click(View view) {
        Fingerprint selected = this.getSelectedFingerprint();
        if (selected == null)
            return;

        try {
            Log.d(TAG, "Trying to get available sub keys!");
            KeyID[] keys = this.authentication.getAvailableSubKeys(selected, null);
            Log.d(TAG, "" + keys.length);

            if (keys.length > 0)
                this.randomSubKey = keys[new Random().nextInt(keys.length)];
        } catch (RemoteException e) {
            Log.e(TAG, "Error", e);
        }
    }

    private KeyID randomSubKey = null;

    public void btnSubKey_Click(View view) {
        Fingerprint selected = this.getSelectedFingerprint();
        if (selected == null)
            return;

        try {
            Log.d(TAG, "Trying to get a random sub key!");
            byte[] key = this.authentication.getSubKey(selected, this.randomSubKey);
        } catch (RemoteException e) {
            Log.e(TAG, "Error", e);
        }
    }

    public void btnRegisterSubKey_Click(View view) {
        Fingerprint selected = this.getSelectedFingerprint();
        if (selected == null)
            return;

        byte[] k = new byte[128];
        new Random().nextBytes(k);

        try {
            Log.d(TAG, "Trying to register a sub key!");
            boolean result = this.authentication.requestSubKeySignature(k, false, "test");
            Log.d(TAG, "- Result " + result);
        } catch (RemoteException e) {
            Log.e(TAG, "Error", e);
        }
    }
}
