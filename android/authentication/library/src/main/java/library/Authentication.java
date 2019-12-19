/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package library;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.util.Log;

/**
 * Authentication class for requesting, accessing and interacting with the sol - service.
 *
 *@author Max Kolhagen
 */
public final class Authentication implements ServiceConnection {
    private static final String TAG = Authentication.class.getSimpleName();

    private static final String SERVICE_PACKAGE = "core.authentication";
    private static final String SERVICE_CLASS = ".AuthenticationService";

    /**
     * Callback listener
     */
    public interface ServiceReceiver {
        void onAuthenticationServiceReceived(AuthenticationService service);

        void onAuthenticationServiceFailure(Exception e);
    }

    /**
     * SINGLETON
     */

    private static Authentication _instance = null;

    /**
     * Use this method to request a connection to the authentication service.
     *
     * @param context
     * @param receiver
     * @return
     */
    public static boolean request(final Context context, final ServiceReceiver receiver) {
        // check if authentication service is installed
        if (!Authentication.isInstalled(context))
            return false;

        // check if already available
        if (Authentication.isAvailable()) {
            // inform listener
            if (receiver != null)
                receiver.onAuthenticationServiceReceived(Authentication._instance.service);

            return true;
        }

        try {
            // instantiate if not already available
            Authentication._instance = new Authentication(context, receiver);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Unable to acquire authentication service!", e);
            return false;
        }
    }

    /**
     * Checks if the service is installed.
     *
     * @param context
     * @return
     */
    public static boolean isInstalled(final Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            pm.getPackageInfo(SERVICE_PACKAGE, PackageManager.GET_SERVICES);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    /**
     * Checks if the service is already available.
     *
     * @return
     */
    public static boolean isAvailable() {
        return (_instance != null && _instance.isConnected());
    }

    // ----

    /**
     * FIELDS
     */

    private AuthenticationService service = null;
    private final ServiceReceiver receiver;

    /**
     * Constructor.
     *
     * @param context
     * @param receiver
     */
    private Authentication(final Context context, final ServiceReceiver receiver) {
        this.receiver = receiver;

        Log.d(TAG, "Binding to service...");

        try {
            // bind to service
            Intent intent = new Intent();
            intent.setClassName(SERVICE_PACKAGE, SERVICE_PACKAGE + SERVICE_CLASS);
            context.bindService(intent, this, Context.BIND_AUTO_CREATE);
        } catch (Exception e) {
            Exception wrapper = new IllegalStateException("Could not connect to Authentication Service! Check if it is installed!", e);

            if (this.receiver != null)
                this.receiver.onAuthenticationServiceFailure(wrapper);
        }
    }

    /**
     * Checks if the service is still connected.
     *
     * @return
     */
    private boolean isConnected() {
        return (this.service != null);
    }

    @Override
    public void onServiceConnected(ComponentName className, IBinder service) {
        // Called when the connection with the service is established
        Log.d(TAG, "Service connected!");

        // Following the example above for an AIDL interface,
        // this gets an instance of the IRemoteInterface, which we can use to call on the service
        this.service = new AuthenticationService(AuthenticationInterface.Stub.asInterface(service));

        if (this.receiver != null)
            this.receiver.onAuthenticationServiceReceived(this.service);
    }

    @Override
    public void onServiceDisconnected(ComponentName className) {
        // Called when the connection with the service disconnects unexpectedly
        Log.e(TAG, "Service was unexpectedly disconnected!");

        this.service = null;
    }
}
