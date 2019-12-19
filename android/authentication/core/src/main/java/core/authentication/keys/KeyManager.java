
/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys;

import android.content.Context;
import android.util.Log;

import core.authentication.keys.security.PRNGFixes;
import core.authentication.trust.ManagerService;
import core.authentication.trust.TrustFileManager;
import primitives.config.Config;
import primitives.helper.AppDetails;
import primitives.helper.InMemoryStorage;
import primitives.keys.Fingerprint;
import primitives.keys.Signature;
import primitives.keys.SignatureParameter;
import primitives.keys.SubKeySignature;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * KeyManager class is the abstract class for all key managers
 *
 *@author Max Kolhagen
 */
public abstract class KeyManager {
    private String TAG = KeyManager.class.getSimpleName();

    static {
        // apply Android PRNG fixes
        PRNGFixes.apply();
    }

    /**
     * FIELDS
     */
    protected final InMemoryStorage imStorage;

    private final String basePath;

    protected PublicKey publicKey = null;
    protected PrivateKey privateKey = null;

    private Signature signature = null;

    /**
     * Constructor.
     *
     * @param basePath
     */
    protected KeyManager(final String basePath) {
        Log.d(TAG, "Initializing KeyManager");

        this.basePath = basePath;

        this.imStorage = InMemoryStorage.getInstance();

        // public key & private key should be loaded by subclasses!
    }

    /**
     * Called when the initialization is complete. Generates self-signature.
     *
     * @param context
     * @throws Exception
     */
    protected final void initializationComplete(Context context) throws Exception {
        Log.d(TAG, "Finishing initialization of KeyManager...");

        final TrustFileManager fileManager = TrustFileManager.getInstance(KeyManager.this.basePath);

        if (fileManager.hasSignature(KeyManager.this.publicKey, KeyManager.this.publicKey)) {
            Log.d(TAG, "- Signature already exists: Loading");
            // check if signature (& public key) have already been stored
            KeyManager.this.signature = fileManager.loadSignature(KeyManager.this.publicKey, KeyManager.this.publicKey);

            KeyManager.this.completeSuccess(context);

            return;
        }

        Log.d(TAG, "- First time, creating self-signature");

        // create new signature and store everything
        KeyManager.this.signature = KeyManager.this.createSignature(KeyManager.this.publicKey, null); // TODO: add my own name
        fileManager.savePublicKey(KeyManager.this.publicKey, KeyManager.this.signature);

        KeyManager.this.completeSuccess(context);
    }

    private final void completeSuccess(Context context) {
        ManagerService.requestManagers(context, null);
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public Signature getSignature() {
        return this.signature;
    }

    public Fingerprint getFingerprint() {
        if (this.signature == null)
            throw new IllegalStateException("Key Manager was not initialized properly!");

        return this.signature.getSubject();
    }

    public boolean isInitialized() {
        if (this.publicKey == null || this.privateKey == null || this.signature == null)
            return false;

        return true;
    }

    protected byte[] sign(byte[] data) throws Exception {
        if (KeyManager.this.privateKey == null)
            throw new IllegalStateException("Key Manager was not initialized properly!");

        SignatureParameter signParams = Config.KEY_SIGNATURE_PARAMETERS;

        java.security.Signature sig = java.security.Signature.getInstance(signParams.getSignatureAlgorithm());
        sig.initSign(KeyManager.this.privateKey);
        sig.update(data);
        return sig.sign();
    }

    /**
     * Creates a new signature.
     *
     * @param subject
     * @param alias
     */
    public Signature createSignature(PublicKey subject, String alias) throws Exception {
        Signature result = new Signature(KeyManager.this.publicKey, subject);
        result.setAlias(alias);
        result.setData(this.sign(result.getDigestData(subject)));
        return result;
    }

    /**
     * Creates a new sub key signature.
     *
     * @param subKey
     * @param appDetails
     * @param bindToApp
     * @param tag
     * @return
     * @throws Exception
     */
    public SubKeySignature createSubKeySignature(byte[] subKey, AppDetails appDetails, boolean bindToApp, String tag) throws Exception {
        SubKeySignature result = new SubKeySignature(this.publicKey, subKey, appDetails);

        result.setBindToApp(bindToApp);
        result.setTag(tag);
        result.setData(this.sign(result.getDigestData(subKey)));

        return result;
    }
}