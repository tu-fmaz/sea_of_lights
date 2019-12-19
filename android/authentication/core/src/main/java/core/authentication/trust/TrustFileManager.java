/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.trust;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

import android.util.Base64;
import android.util.Base64InputStream;
import android.util.Base64OutputStream;
import android.util.Log;
import core.authentication.exceptions.SecurityException;
import primitives.config.Config;
import primitives.helper.Utils;
import primitives.keys.Fingerprint;
import primitives.keys.KeyID;
import primitives.keys.Signature;
import primitives.keys.SubKeySignature;

/**
 * TrustFileManager class handles all file operations for the Trust Management Layer (repository).
 *
 *@author Max Kolhagen
 */
public final class TrustFileManager {
    private String TAG = TrustFileManager.class.getSimpleName();

    // ---- SINGLETON

    private static volatile Map<String, TrustFileManager> _instances = new HashMap<>();

    public static synchronized TrustFileManager getInstance(final String basePath) {
        if (_instances.containsKey(basePath))
            return _instances.get(basePath);

        TrustFileManager entry = new TrustFileManager(basePath);
        _instances.put(basePath, entry);
        return entry;
    }

    // ---- CONSTRUCTOR

    private final File trustDir;

    private TrustFileManager(final String basePath) {
        Log.d(TAG, "Creating a new FileManager instance at: " + basePath);

        this.TAG += "/" + basePath.substring(basePath.length() - 4, basePath.length());

        this.trustDir = new File(basePath, Config.TRUST_PATH);

        if (this.trustDir.exists() && !this.trustDir.isDirectory())
            throw new IllegalArgumentException();

        if (!this.trustDir.exists())
            this.trustDir.mkdirs();
    }

    // --- SIGNATURE

    public boolean saveSignature(Signature signature) throws Exception {
        if (signature == null)
            throw new IllegalArgumentException();

        String path = signature.getSubject().toString() + "/" + signature.getIssuer().toString() + ".sig";
        return this.saveFileObject(path, signature);
    }

    public boolean deleteSignature(Signature signature) {
        String path = signature.getSubject().toString() + "/" + signature.getIssuer().toString() + ".sig";
        return this.deleteFile(path);
    }

    public Signature loadSignature(PublicKey issuer, PublicKey subject) throws Exception {
        if (issuer == null || subject == null)
            throw new IllegalArgumentException();

        Fingerprint fpIssuer = new Fingerprint(issuer);
        Fingerprint fpSubject = new Fingerprint(subject);

        Signature result = this.loadSignature(fpIssuer, fpSubject);

        if (Config.TRUST_EXTRA_SECURITY && !result.verify(issuer, subject))
            throw new SignatureException("Verify signature failed!");

        return result;
    }

    public Signature loadSignature(Fingerprint issuer, Fingerprint subject) throws Exception {
        if (issuer == null || subject == null)
            throw new IllegalArgumentException();

        String path = subject.toString() + "/" + issuer.toString() + ".sig";
        Signature result = (Signature) this.readFileObject(path);
        if (Config.TRUST_EXTRA_SECURITY && (!result.getIssuer().equals(issuer) || !result.getSubject().equals(subject)))
            throw new SecurityException("Fingerprints do not match loaded signature!");

        return result;
    }

    public boolean hasSignature(PublicKey issuer, PublicKey subject) throws Exception {
        if (issuer == null || subject == null)
            throw new IllegalArgumentException();

        Fingerprint fpIssuer = new Fingerprint(issuer);
        Fingerprint fpSubject = new Fingerprint(subject);

        String path = fpSubject.toString() + "/" + fpIssuer.toString() + ".sig";
        File file = new File(this.trustDir, path);
        if (!file.exists() || !file.isFile())
            return false;

        return true;
    }

    // --- PUBLIC KEY

    public boolean savePublicKey(PublicKey publicKey, Signature selfSignature) throws Exception {
        if (publicKey == null)
            throw new IllegalArgumentException();

        if (!selfSignature.getIssuer().equals(selfSignature.getSubject()))
            throw new SecurityException("Not a self-signature!");

        Fingerprint fp = new Fingerprint(publicKey);
        if (!selfSignature.getSubject().equals(fp))
            throw new SecurityException("Given fingerprint does not match PublicKey: " + fp);

        String path = selfSignature.getSubject().toString() + "/keys/public.key";
        boolean result = this.saveFileObject(path, publicKey);
        return result && this.saveSignature(selfSignature);
    }

    public boolean deleteSubject(Fingerprint fingerprint) {
        return this.deleteFile(fingerprint.toString());
    }

    public PublicKey loadPublicKey(Fingerprint fingerprint) throws Exception {
        if (fingerprint == null)
            throw new IllegalArgumentException();

        String path = fingerprint.toString() + "/keys/public.key";
        PublicKey publicKey = (PublicKey) this.readFileObject(path);

        if (Config.TRUST_EXTRA_SECURITY && !(new Fingerprint(publicKey).equals(fingerprint)))
            throw new SecurityException("Loaded PublicKey is inconsistent with given fingerprint: " + fingerprint);

        return publicKey;
    }

    // --- SUB KEY SIGNATURE

    public boolean saveSubKey(byte[] publicSubKey, SubKeySignature signature) throws Exception {
        if (publicSubKey == null || signature == null)
            throw new IllegalArgumentException();

        KeyID keyID = new KeyID(publicSubKey);
        if (!keyID.equals(signature.getSubKey()))
            throw new SecurityException("Given KeyID does not match PublicKey: " + keyID);

        String path = signature.getOwner().toString() + "/keys/" + signature.getSubKey().toString();

        boolean result = this.saveFileObject(path + ".sig", signature);
        return result && this.saveFileObject(path + ".key", publicSubKey);
    }

    public SubKeySignature loadSubKeySignature(PublicKey owner, byte[] publicSubKey) throws Exception {
        if (owner == null || publicSubKey == null)
            throw new IllegalArgumentException();

        Fingerprint fingerprint = new Fingerprint(owner);
        KeyID keyID = new KeyID(publicSubKey);

        String path = fingerprint.toString() + "/keys/" + keyID + ".sig";
        SubKeySignature result = (SubKeySignature) this.readFileObject(path);

        if (Config.TRUST_EXTRA_SECURITY && !result.verify(owner, publicSubKey))
            throw new SignatureException("Verify SubKey signature failed!");

        return result;
    }

    // --- SUB KEY PUBLIC KEY

    public byte[] loadPublicSubKey(Fingerprint owner, KeyID keyID) throws Exception {
        if (owner == null || keyID == null)
            throw new IllegalArgumentException();

        String path = owner.toString() + "/keys/" + keyID + ".key";
        byte[] publicKey = (byte[]) this.readFileObject(path);

        if (Config.TRUST_EXTRA_SECURITY && !(new KeyID(publicKey).equals(keyID)))
            throw new SecurityException("Loaded PublicKey is inconsistent with given KeyID: " + keyID);

        return publicKey;
    }

    // --- GENERIC STORE / READ / DELETE

    private Object readFileObject(String relativePath) throws Exception {
        File file = new File(this.trustDir, relativePath);
        if (!file.exists() || !file.isFile())
            throw new FileNotFoundException(relativePath);

        FileInputStream fis = new FileInputStream(file);
        Base64InputStream bis = new Base64InputStream(fis, Base64.NO_WRAP);
        ObjectInputStream ois = new ObjectInputStream(bis);
        Object result = ois.readObject();
        ois.close();
        bis.close();
        fis.close();

        return result;
    }

    private boolean saveFileObject(String relativePath, Object object) throws Exception {
        File file = new File(this.trustDir, relativePath);
        if (file.exists())
            return false;

        if (!file.exists() && !file.getParentFile().exists())
            file.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(file);
        Base64OutputStream bos = new Base64OutputStream(fos, Base64.NO_WRAP);
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(object);
        oos.close();
        bos.close();
        fos.close();

        return true;
    }

    private boolean deleteFile(String relativePath) {
        File file = new File(this.trustDir, relativePath);

        if (!file.isDirectory())
            return file.delete();

        try {
            Utils.deleteDirectory(file);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Could not delete directory: " + file.getAbsolutePath());
            return false;
        }
    }
}
