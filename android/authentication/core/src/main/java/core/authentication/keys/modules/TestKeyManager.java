/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.modules;

import android.content.Context;
import android.util.Log;

import core.authentication.keys.KeyManager;
import primitives.config.Config;
import primitives.keys.SignatureParameter;

import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

/**
 * TestKeyManager class implements a Software-only keystore w/o a password for testing purposes.
 *
 *@author Max Kolhagen
 */
public class TestKeyManager extends KeyManager {
    private static final String TAG = TestKeyManager.class.getSimpleName();

    static {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }

    private static final String SW_KEYSTORE = "authentication.bks";
    private static final String SW_KEYSTORE_TYPE = "BouncyCastle";
    private static final String SW_PROVIDER = "SC";
    private static final String SW_ALIAS = "authenticationKey00";
    private static final X500Principal SW_CERT_SUBJECT = new X500Principal("CN=Authentication");

    private String password = "password";
    private final SignatureParameter parameter;

    public TestKeyManager(final Context context, String basePath) throws Exception {
        super(basePath);

        this.parameter = Config.KEY_SIGNATURE_PARAMETERS;

        // check if a keystore file already exists!
        boolean keyStoreAvailable = false;
        try {
            context.openFileInput(SW_KEYSTORE);
            keyStoreAvailable = true;
        } catch (FileNotFoundException e) {
            // swallow
        }

        Log.d(TAG, "Initializing SoftwareKeyManager - KeyStore available: " + keyStoreAvailable);

        if (keyStoreAvailable) {
            this.loadAuthenticationKey(context);
        } else {
            this.createAuthenticationKey(context);
        }

        this.initializationComplete(context);
    }

    @Override
    protected byte[] sign(byte[] data) throws Exception {
        if (this.privateKey == null)
            throw new IllegalStateException("Key Manager was not initialized properly!");

        Signature s = Signature.getInstance(this.parameter.getSignatureAlgorithm(), SW_PROVIDER);
        s.initSign(this.privateKey);
        s.update(data);
        return s.sign();
    }

    private void createAuthenticationKey(final Context context) throws Exception {
        Log.d(TAG, "createAuthenticationKey");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(this.parameter.getAlgorithm(), SW_PROVIDER);
        kpg.initialize(this.parameter.getKeySize());
        KeyPair kp = kpg.generateKeyPair();

        final KeyStore keyStore = KeyStore.getInstance(SW_KEYSTORE_TYPE, SW_PROVIDER);
        final KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(this.password.toCharArray());
        // do key store magic
        keyStore.load(null, null);

        // passwords are necessary!
        Certificate certificate = this.createCertificate(kp.getPublic());
        keyStore.setEntry(SW_ALIAS, new KeyStore.PrivateKeyEntry(kp.getPrivate(), new Certificate[]{certificate}),
                protection);

        OutputStream ostream = context.openFileOutput(SW_KEYSTORE, Context.MODE_PRIVATE);
        keyStore.store(ostream, this.password.toCharArray());
        ostream.close();

        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
    }

    private Certificate createCertificate(PublicKey publicKey) throws Exception {
        // signing w/ ECDSA here would lead to weird exception, so we cheat
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", SW_PROVIDER);
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();

        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);

        X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(SW_CERT_SUBJECT,
                BigInteger.ONE, start.getTime(), end.getTime(), SW_CERT_SUBJECT, publicKey);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());

        X509CertificateHolder ch = cb.build(signer);
        return new JcaX509CertificateConverter().getCertificate(ch);
    }

    private void loadAuthenticationKey(Context context) throws Exception {
        Log.d(TAG, "loadAuthenticationKey");

        KeyStore ks = KeyStore.getInstance(SW_KEYSTORE_TYPE, SW_PROVIDER);
        final KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(this.password.toCharArray());

        InputStream istream = context.openFileInput(SW_KEYSTORE);
        ks.load(istream, this.password.toCharArray());

        KeyStore.Entry entry = ks.getEntry(SW_ALIAS, protection);
        if (!(entry instanceof KeyStore.PrivateKeyEntry))
            throw new IllegalStateException("Unable to load key from keystore!");

        this.privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        Certificate certificate = ((KeyStore.PrivateKeyEntry) entry).getCertificate();
        this.publicKey = certificate.getPublicKey();

        istream.close();
    }
}
