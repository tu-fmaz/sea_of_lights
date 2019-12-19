/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.trust;

import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.support.annotation.Nullable;
import android.util.Log;

import core.authentication.keys.KeyManager;
import core.authentication.keys.KeyManagerPriority;
import primitives.helper.InMemoryStorage;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * ManagerService class is the service that manages the instances for both the Trust & Key Management.
 *
 *@author Max Kolhagen
 */
public class ManagerService extends Service {
    private static final String TAG = ManagerService.class.getSimpleName();
    private static final String PACKAGE = ManagerService.class.getPackage().getName();

    public static final String ACTION_GET_MANAGERS = PACKAGE + ".action.GET_MANAGERS";

    private static final String ACTION_REQUEST_MANAGERS = PACKAGE + ".action.REQUEST_MANAGERS";
    private static final String EXTRA_LISTENER = PACKAGE + ".extra.LISTENER";

    /**
     * Actual wrapper class for the managers.
     */
    public static final class Managers {
        protected TrustManager trustManager = null;
        protected KeyManager keyManager = null;

        private Managers() {
            // hide
        }

        public boolean isInitialized() {
            return this.trustManager != null && this.keyManager != null;
        }

        public TrustManager getTrustManager() {
            return this.trustManager;
        }

        public KeyManager getKeyManager() {
            return this.keyManager;
        }

        // ---- SINGLETON

        private static Managers _instance = null;

        public static Managers getInstance() {
            if (_instance == null)
                _instance = new Managers();

            return _instance;
        }
    }

    /**
     * FIELDS
     */

    private Managers manager = null;
    private Set<PendingIntent> listeners = new HashSet<>();
    private Object MUTEX_MANAGER = new Object();

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);

        Log.d(TAG, "onStartCommand - " + intent);

        this.manager = Managers.getInstance();

        try {
            this.handleAction(intent);
        } catch (Exception e) {
            Log.e(TAG, "Could not handle action!", e);
        }

        return Service.START_STICKY;
    }

    /**
     * Dispatch incoming intents.
     *
     * @param intent
     * @throws Exception
     */
    private void handleAction(Intent intent) throws Exception {
        if (intent == null || intent.getAction() == null)
            return;

        final String action = intent.getAction();

        if (!ACTION_REQUEST_MANAGERS.equals(action))
            return;

        // register listener (if available)
        if (intent.hasExtra(EXTRA_LISTENER)) {
            PendingIntent listener = intent.getParcelableExtra(EXTRA_LISTENER);
            this.listeners.add(listener);
        }

        synchronized (MUTEX_MANAGER) {
            // check if already initialized
            if (this.manager.isInitialized()) {
                this.notifyListeners();
                return;
            }

            Log.d(TAG, "Initializing managers...");

            final String basePath = this.getFilesDir().getAbsolutePath();

            // instantiate key manager
            this.manager.keyManager = KeyManagerPriority.getPriorityKeyManager(this, basePath);
            if (this.manager.keyManager == null) {
                Log.w(TAG, "Could not instantiate Key Manager!");
                return;
            }

            // put fingerprint into in-memory storage
            InMemoryStorage.getInstance().put(InMemoryStorage.FINGERPRINT, this.manager.getKeyManager().getFingerprint());

            this.manager.trustManager = new TrustManager(basePath, this.manager.keyManager.getPublicKey());
            this.manager.trustManager.initialize();
            this.notifyListeners();
        }
    }

    /**
     * Notify registered listeners that the managers are finally available.
     */
    private void notifyListeners() {
        Log.d(TAG, "notifyListeners - " + this.listeners.size());

        Iterator<PendingIntent> iterator = this.listeners.iterator();
        while (iterator.hasNext()) {
            PendingIntent intent = iterator.next();

            try {
                if (intent != null)
                    intent.send(this, 0, null);
            } catch (Exception e) {
                Log.e(TAG, "Could not inform listener!", e);
            }

            iterator.remove();
        }
    }

    // ----

    /**
     * Static method to request instantiating the managers.
     *
     * @param context
     * @param listener
     */
    public static void requestManagers(Context context, PendingIntent listener) {
        Intent intent = new Intent(context, ManagerService.class);
        intent.setAction(ACTION_REQUEST_MANAGERS);
        if (listener != null)
            intent.putExtra(EXTRA_LISTENER, listener);

        context.startService(intent);
    }
}
