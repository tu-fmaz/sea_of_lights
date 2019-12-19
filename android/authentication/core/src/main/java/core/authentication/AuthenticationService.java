/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication;

import android.app.ActivityManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import core.authentication.keys.KeyManager;
import core.authentication.trust.ManagerService;
import core.authentication.trust.TrustManager;
import core.authentication.trust.TrustProtocolService;
import library.AuthenticationInterface;
import primitives.helper.AppDetails;
import primitives.helper.ObjectWrapper;
import primitives.keys.Fingerprint;
import primitives.keys.KeyID;
import primitives.keys.SubKeySignature;
import primitives.trust.MetaInformation;
import primitives.trust.TrustInfo;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * AuthenticationService class implements the SoL service
 *
 *@author Max Kolhagen
 */
public class AuthenticationService extends Service {
    private static final String TAG = AuthenticationService.class.getSimpleName();

    /**
     * FIELDS
     */

    private ManagerService.Managers managers = null;

    private Map<Long, AppDetails> appDetailsCache = new HashMap<>();

    @Override
    public void onCreate() {
        Log.d(TAG, "onCreate()");
        super.onCreate();

        // check if the managers are available
        this.checkManagers();
    }

    /**
     * Check if the managers are available (Trust & Key Management).
     *
     * @return
     */
    private boolean checkManagers() {
        this.managers = ManagerService.Managers.getInstance();
        if (this.managers != null && this.managers.isInitialized())
            return true;

        // if not, request them...
        Intent intent = new Intent(this, AuthenticationService.class);
        intent.setAction(ManagerService.ACTION_GET_MANAGERS);
        PendingIntent pending = PendingIntent.getService(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
        ManagerService.requestManagers(this, pending);
        return false;
    }

    @Override
    public IBinder onBind(Intent intent) {
        Log.d(TAG, "onBind()");

        // return the interface
        return this.mBinder;
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy()");
        super.onDestroy();
    }

    @Override
    public boolean onUnbind(Intent intent) {
        Log.d(TAG, "onUnbind()");
        return super.onUnbind(intent);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        int result = super.onStartCommand(intent, flags, startId);

        Log.d(TAG, "onStartCommand - " + intent);

        // check availability of the managers again
        if (intent != null && intent.getAction() != null &&
                intent.getAction().equals(ManagerService.ACTION_GET_MANAGERS))
            this.checkManagers();

        return result;
    }

    /**
     * STUB FOR THE SERVICE
     */

    private AuthenticationInterface.Stub mBinder = new AuthenticationInterface.Stub() {
        @Override
        public boolean isInitialized() throws RemoteException {
            Log.d(TAG, "(SERVICE) isInitialized");
            return AuthenticationService.this.checkManagers();
        }

        @Override
        public boolean performHandshake(ObjectWrapper fingerprint) throws RemoteException {
            if (!this.isInitialized())
                throw new IllegalStateException("AuthenticationService is not yet initialized!");

            Log.d(TAG, "(SERVICE) performHandshake");

            Fingerprint subject = (Fingerprint) fingerprint.getObject();

            TrustProtocolService.performHandshake(AuthenticationService.this, subject);

            return true;
        }

        @Override
        public ObjectWrapper getTrustInfo(ObjectWrapper fingerprint) throws RemoteException {
            if (!this.isInitialized())
                throw new IllegalStateException("AuthenticationService is not yet initialized!");

            Log.d(TAG, "(SERVICE) getTrustInfo");

            final TrustManager tm = AuthenticationService.this.managers.getTrustManager();
            Fingerprint subject = (Fingerprint) fingerprint.getObject();

            TrustInfo result = tm.getTrustInfo(subject);

            return new ObjectWrapper(result);
        }

        @Override
        public ObjectWrapper getMetaInformation(ObjectWrapper fingerprint) throws RemoteException {
            if (!this.isInitialized())
                throw new IllegalStateException("AuthenticationService is not yet initialized!");

            Log.d(TAG, "(SERVICE) getMetaInformation");

            final TrustManager tm = AuthenticationService.this.managers.getTrustManager();
            Fingerprint subject = (Fingerprint) fingerprint.getObject();

            MetaInformation result = tm.getMetaInformation(subject);

            return new ObjectWrapper(result);
        }

        @Override
        public boolean requestSubKeySignature(byte[] publicSubKey, boolean bindToApp, String tag) throws RemoteException {
            if (!this.isInitialized())
                throw new IllegalStateException("AuthenticationService is not yet initialized!");

            Log.d(TAG, "(SERVICE) requestSubKeySignature");

            final KeyManager km = AuthenticationService.this.managers.getKeyManager();
            final TrustManager tm = AuthenticationService.this.managers.getTrustManager();

            AppDetails details = AuthenticationService.this.getAppDetails(Binder.getCallingPid(), Binder.getCallingUid());

            try {
                // create signature
                SubKeySignature signature = km.createSubKeySignature(publicSubKey, details, bindToApp, tag);

                return tm.addSubKey(publicSubKey, signature);
            } catch (Exception e) {
                Log.e(TAG, "Could not create SubKeySignature!", e);
                return false;
            }
        }

        @Override
        public ObjectWrapper getAvailableSubKeys(ObjectWrapper fingerprint, String tag) throws RemoteException {
            if (!this.isInitialized())
                throw new IllegalStateException("AuthenticationService is not yet initialized!");

            Log.d(TAG, "(SERVICE) getAvailableSubKeys");

            final TrustManager tm = AuthenticationService.this.managers.getTrustManager();

            Fingerprint owner = (Fingerprint) fingerprint.getObject();

            AppDetails details = AuthenticationService.this.getAppDetails(Binder.getCallingPid(), Binder.getCallingUid());

            Set<KeyID> subKeys = tm.getAvailableSubKeys(owner, details, tag);

            if (subKeys == null)
                return null;

            return new ObjectWrapper(subKeys.toArray(new KeyID[subKeys.size()]));
        }

        @Override
        public byte[] getSubKey(ObjectWrapper fingerprint, ObjectWrapper keyID) throws RemoteException {
            if (!this.isInitialized())
                throw new IllegalStateException("AuthenticationService is not yet initialized!");

            Log.d(TAG, "(SERVICE) getSubKey");

            final TrustManager tm = AuthenticationService.this.managers.getTrustManager();

            Fingerprint owner = (Fingerprint) fingerprint.getObject();
            KeyID requestedSubKey = (KeyID) keyID.getObject();

            AppDetails details = AuthenticationService.this.getAppDetails(Binder.getCallingPid(), Binder.getCallingUid());

            try {
                return tm.getSubKey(owner, requestedSubKey, details);
            } catch (Exception e) {
                Log.e(TAG, "Unable to load public SubKey!", e);
                return null;
            }
        }
    };

    /**
     * Provides detailed information about the binding application.
     *
     * @param pid
     * @param uid
     * @return
     */
    private AppDetails getAppDetails(final int pid, final int uid) {
        // TODO: What happens when two bind at the same time?
        final Long identifier = (((long) pid) << 32) | (uid & 0xffffffffL);
        if (this.appDetailsCache.containsKey(identifier))
            return this.appDetailsCache.get(identifier);

        Log.d(TAG, "Looking up app data for " + String.format("UID: %d, PID: %d", uid, pid));

        final PackageManager pm = this.getPackageManager();
        //String name = pm.getNameForUid(uid); = shared UID -or- PN!

        // get all associated PNs for UID (> 1 if shared UID)
        String[] packageNamesFromUID = pm.getPackagesForUid(uid);

        Log.d(TAG, "UID - Packages found: " + packageNamesFromUID.length);

        if (packageNamesFromUID.length == 0)
            return null;

        // get all associated PNs for PID
        List<String> packageNamesFromPID = new ArrayList<>();
        final ActivityManager am = (ActivityManager) this.getSystemService(ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> processes = am.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo process : processes) {
            // --- start sec1: only for locally test ---
            if(packageNamesFromPID.size() == 0)
                packageNamesFromPID.add(process.processName);
            // --- end sec1
            if (process.pid != pid)
                continue;

            packageNamesFromPID.add(process.processName);
        }

        Log.d(TAG, "PID - Packages found: " + packageNamesFromPID.size());

        // --- start sec2: only for locally test ---
        List<String> packageNamesFromPIDCopy = new ArrayList<>();
        packageNamesFromPIDCopy.addAll(packageNamesFromPID);
        // --- end sec2

        // --- start sec3: here should be packageNamesFromPID
        packageNamesFromPIDCopy.retainAll(Arrays.asList(packageNamesFromUID));

        Log.d(TAG, "UID - PID Intersection: " + packageNamesFromPID.size());

        if (packageNamesFromPID.size() == 0)
            return null;

        AppDetails result = new AppDetails(packageNamesFromPID.get(0));

        try {
            ApplicationInfo ai = pm.getApplicationInfo(result.packageName, 0);
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "Could not read app name!", e);
        }

        try {
            PackageInfo info = pm.getPackageInfo(result.packageName, PackageManager.GET_SIGNATURES);

            if (info.signatures.length > 0) {
                byte[] signature = info.signatures[0].toByteArray();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                Certificate cert = cf.generateCertificate(new ByteArrayInputStream(signature));
                result.signatureKeyFingerprint = new Fingerprint(cert.getPublicKey());
            }
        } catch (Exception e) {
            Log.e(TAG, "Could not read app signature", e);
        }

        this.appDetailsCache.put(identifier, result);
        return result;
    }
}
