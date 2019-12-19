/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package wifi;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;

import primitives.keys.Fingerprint;

import java.util.Map;
import java.util.Random;

/**
 * Activity class for (standalone) testing the wifi service.
 */
/**
 * MainActivity class for (standalone) testing the wifi service.
 *
 *@author Max Kolhagen
 */
public class MainActivity extends Activity {
    private static final String TAG = MainActivity.class.getSimpleName();

    private static final int WIFI_REQUEST_NEIGHBORS = 0x10;
    private static final int WIFI_REQUEST_INFO = 0x20;

    private static final String WIFI_PACKAGE_NAME = "wifi";
    private static final String WIFI_SERVICE_NAME = "wifi.WifiP2pService";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    /**
     * Starts the service.
     *
     * @param view
     */
    public void btnStart_Click(View view) {
        WifiP2pService.startService(this);
    }

    /**
     * Triggers a discovery.
     *
     * @param view
     */
    public void btnDiscover_Click(View view) {
        Intent intent = new Intent();
        intent.setClassName(WIFI_PACKAGE_NAME, WIFI_SERVICE_NAME);
        intent.setAction(WifiP2pService.ACTION_DISCOVER);
        this.startService(intent);
    }

    /**
     * Get information about a single node.
     *
     * @param view
     */
    public void btnInformation_Click(View view) {
        PendingIntent result = this.createPendingResult(WIFI_REQUEST_INFO, new Intent(), PendingIntent.FLAG_ONE_SHOT);

        // random fingerprint bytes
        byte[] fpBuffer = new byte[Fingerprint.SIZE];
        new Random().nextBytes(fpBuffer);

        Intent intent = new Intent();
        intent.setClassName(WIFI_PACKAGE_NAME, WIFI_SERVICE_NAME);
        intent.setAction(WifiP2pService.ACTION_GET_INFO);
        intent.putExtra(WifiP2pService.EXTRA_RESULT, result);
        intent.putExtra(WifiP2pService.EXTRA_RESULT_INFO_FP, Fingerprint.fromData(fpBuffer));
        this.startService(intent);
    }

    /**
     * Get all current neighbors.
     *
     * @param view
     */
    public void btnNeighbors_Click(View view) {
        PendingIntent result = this.createPendingResult(WIFI_REQUEST_NEIGHBORS, new Intent(), PendingIntent.FLAG_ONE_SHOT);

        Intent intent = new Intent();
        intent.setClassName(WIFI_PACKAGE_NAME, WIFI_SERVICE_NAME);
        intent.setAction(WifiP2pService.ACTION_GET_NEIGHBORS);
        intent.putExtra(WifiP2pService.EXTRA_RESULT, result);
        this.startService(intent);
    }

    /**
     * Trigger an update of the fingerprints and IP addresses.
     *
     * @param view
     */
    public void btnUpdate_Click(View view) {
        Intent intent = new Intent();
        intent.setClassName(WIFI_PACKAGE_NAME, WIFI_SERVICE_NAME);
        intent.setAction(WifiP2pService.ACTION_UPDATE);
        this.startService(intent);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        Log.d(TAG, "onActivityResult: " + requestCode + ", " + resultCode + ", " + data);

        super.onActivityResult(requestCode, resultCode, data);

        // got a result from the service:
        if (requestCode == WIFI_REQUEST_NEIGHBORS) {
            Log.d(TAG, "- Got neighbors!");
            if (!data.hasExtra(WifiP2pService.EXTRA_RESULT_NEIGHBORS))
                return;
            Map<String, Fingerprint> neighbors = (Map) data.getSerializableExtra(WifiP2pService.EXTRA_RESULT_NEIGHBORS);
            if (neighbors == null)
                return;
            for (String address : neighbors.keySet()) {
                Log.d(TAG, " - " + address + " = " + neighbors.get(address));
            }
        } else if (requestCode == WIFI_REQUEST_INFO) {
            String info = data.getStringExtra(WifiP2pService.EXTRA_RESULT_INFO);
            Log.d(TAG, "- Got info: " + info);
        } else {
            Log.w(TAG, "- Got unknown request code!");
        }
    }
}
