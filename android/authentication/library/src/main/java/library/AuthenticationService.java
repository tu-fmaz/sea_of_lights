/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package library;

import android.os.RemoteException;

import java.util.HashMap;

import primitives.helper.ObjectWrapper;
import primitives.keys.Fingerprint;
import primitives.keys.KeyID;
import primitives.trust.MetaInformation;
import primitives.trust.TrustInfo;

/**
 * AuthenticationService Wrapper class for the sol - service stub.
 *
 *@author Max Kolhagen
 */
public class AuthenticationService {
    // holds the actual stub
    private final AuthenticationInterface mInterface;

    public AuthenticationService(AuthenticationInterface iface) {
        if (iface == null)
            throw new IllegalArgumentException("Interface cannot be null!");

        this.mInterface = iface;
    }

    public boolean isInitialized() throws RemoteException {
        return this.mInterface.isInitialized();
    }

    public boolean performHandshake(Fingerprint fingerprint) throws RemoteException {
        ObjectWrapper wFingerprint = new ObjectWrapper(fingerprint);

        return this.mInterface.performHandshake(wFingerprint);
    }

    public TrustInfo getTrustInfo(Fingerprint fingerprint) throws RemoteException {
        ObjectWrapper wFingerprint = new ObjectWrapper(fingerprint);

        ObjectWrapper result = this.mInterface.getTrustInfo(wFingerprint);

        return (TrustInfo) result.getObject();
    }

    public MetaInformation getMetaInformation(Fingerprint fingerprint) throws RemoteException {
        ObjectWrapper wFingerprint = new ObjectWrapper(fingerprint);

        ObjectWrapper result = this.mInterface.getMetaInformation(wFingerprint);

        MetaInformation metaInformation = new MetaInformation((HashMap)result.getObject());

        return metaInformation;
    }

    public boolean requestSubKeySignature(byte[] publicSubKey, boolean bindToApp, String tag) throws RemoteException {
        return this.mInterface.requestSubKeySignature(publicSubKey, bindToApp, tag);
    }

    public KeyID[] getAvailableSubKeys(Fingerprint fingerprint, String tag) throws RemoteException {
        ObjectWrapper wFingerprint = new ObjectWrapper(fingerprint);

        ObjectWrapper wResult = this.mInterface.getAvailableSubKeys(wFingerprint, tag);

        return (KeyID[]) wResult.getObject();
    }

    public byte[] getSubKey(Fingerprint fingerprint, KeyID keyID) throws RemoteException {
        ObjectWrapper wFingerprint = new ObjectWrapper(fingerprint);
        ObjectWrapper wKeyID = new ObjectWrapper(keyID);

        return this.mInterface.getSubKey(wFingerprint, wKeyID);
    }
}
