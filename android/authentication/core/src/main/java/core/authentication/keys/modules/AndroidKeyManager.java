/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.modules;

import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import core.authentication.exceptions.KeyNotFoundException;
import core.authentication.keys.KeyManager;
import primitives.config.Config;
import primitives.keys.SignatureParameter;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

/**
 * AndroidKeyManager class implements Key Manager using the official Android API Keystore.
 *
 *@author Max Kolhagen
 */
public class AndroidKeyManager extends KeyManager {

    // Constant for logging
    private static final String TAG = SoftwareKeyManager.class.getSimpleName();
    // Constants for certificate generation
    private static final String AD_KEYSTORE_TYPE = "AndroidKeyStore";
    private static final String AD_ALIAS = "authenticationKey00";
    private static final X500Principal AD_CERT_SUBJECT = new X500Principal("CN=Authentication");

    // Local variable for signature algorithm
    private final SignatureParameter parameter;

    /**
     * Constructor
     * */
    public AndroidKeyManager(final Context context, String basePath) throws Exception {
        super(basePath);

        this.parameter = Config.KEY_SIGNATURE_PARAMETERS;

        // check if a keystore file already exists!
        boolean keyStoreAvailable = false;

        try {
            KeyguardManager keyguardMgr = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
            Log.d(TAG, "KeyguardManager - Secure: " + keyguardMgr.isKeyguardSecure());
            Log.d(TAG, "KeyguardManager - Locked: " + keyguardMgr.isKeyguardLocked());

            if (!keyguardMgr.isKeyguardSecure()) {
                // show notification + Intent to secure device
                Intent intent = new Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD);
                context.startActivity(intent);
                // TODO: show notification to restart managerservice
                return;
            }

            if (keyguardMgr.isKeyguardLocked()) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    Intent intent = keyguardMgr.createConfirmDeviceCredentialIntent("Key Authentication", "Please confirm your credentials in order to access your authentication key!");
                    context.startActivity(intent);
                } else {
                    // show notification + click here to restart
                }
                // TODO: show notification to restart managerservice

                return;
            }

            keyStoreAvailable = isKeyStoreAvailable();
            // try to load key from keystore
            if(keyStoreAvailable){
                this.loadAuthenticationKey();
            } else{
                this.saveAuthenticationKey(context);
            }
            this.initializationComplete(context);

        } catch (KeyNotFoundException e) {
            // proceed to creating the key
            Log.d(TAG, "KeyStore is empty: "+ e);
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * Generates and saves authentication key according to the Android version
     * */
    private void saveAuthenticationKey(Context context) throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {// 23+
            this.savePostMarshmallow();
            return;
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) { // 19-22
            this.savePreMarshmallow(context);
            return;
        }

        throw new UnsupportedOperationException("Android Key Manager not supported for version " + Build.VERSION.SDK_INT);
    }

    /**
     * Generates authentication key for Android versions from 4.3 on
     * */
    @TargetApi(Build.VERSION_CODES.M)
    private void savePostMarshmallow() throws Exception {
        Log.d(TAG, "savePostMarshmallow");

        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                AD_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setUserAuthenticationRequired(true)
                // Fingerprint required for auth. for every use
                .setUserAuthenticationValidityDurationSeconds(300)
                .setKeyValidityStart(start.getTime())
                .setKeyValidityForOriginationEnd(end.getTime())
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(this.parameter.getKeySize())
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .build();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                this.parameter.getAlgorithm(), AD_KEYSTORE_TYPE);
        kpg.initialize(spec);

        KeyPair kp = kpg.generateKeyPair();

        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();

        // A known bug in Android 6.0 (API Level 23) see Android doc
        this.publicKey  = KeyFactory.getInstance(this.publicKey.getAlgorithm()).generatePublic(
                new X509EncodedKeySpec(this.publicKey.getEncoded()));
    }

    /**
     * Generates authentication key for Android versions before 4.3
     * */
    @TargetApi(Build.VERSION_CODES.KITKAT)
    @SuppressWarnings("WrongConstant")
    private void savePreMarshmallow(Context context) throws Exception {
        Log.d(TAG, "savePreMarshmallow");

        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        KeyPairGeneratorSpec spec =
                new KeyPairGeneratorSpec.Builder(context)
                        .setKeyType(this.parameter.getAlgorithm())
                        .setKeySize(this.parameter.getKeySize())
                        .setAlias(AD_ALIAS)
                        .setSubject(AD_CERT_SUBJECT)
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .setEncryptionRequired()
                        .build();

        // workaround, RSA here but in reality EC (see above)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                "RSA", AD_KEYSTORE_TYPE);
        kpg.initialize(spec);
        KeyPair kp = kpg.generateKeyPair();

        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
    }

    /**
     * Tries to laod authentication key from keystore
     * */
    private void loadAuthenticationKey() throws Exception {
        Log.d(TAG, "loadAuthenticationKey ");

        KeyStore ks = KeyStore.getInstance(AD_KEYSTORE_TYPE);
        ks.load(null);

        KeyStore.Entry entry = ks.getEntry(AD_ALIAS,null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry))
            throw new KeyNotFoundException("Unable to load key from keystore!");

        this.privateKey = (PrivateKey) ks.getKey(AD_ALIAS, null);;
        this.publicKey = ks.getCertificate(AD_ALIAS).getPublicKey();
    }

    private boolean isKeyStoreAvailable() throws Exception {
        KeyStore ks = KeyStore.getInstance(AD_KEYSTORE_TYPE);
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(AD_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return false;
        }
        return true;
    }
}
