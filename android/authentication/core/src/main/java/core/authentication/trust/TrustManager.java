/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.trust;

import java.io.File;
import java.io.Serializable;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

import android.util.Log;

import core.authentication.trust.entries.SubKeyEntry;
import core.authentication.trust.entries.Subject;
import primitives.config.Config;
import primitives.helper.AppDetails;
import primitives.keys.Fingerprint;
import primitives.keys.KeyID;
import primitives.keys.Signature;
import primitives.keys.SubKeySignature;
import primitives.trust.MetaInformation;
import primitives.trust.TrustInfo;
import primitives.trust.TrustLevel;

/**
 * TrustManager class represents the trust repository.
 *
 *@author Max Kolhagen
 */
public final class TrustManager {
    private static final String TAG = TrustManager.class.getSimpleName();

    /**
     * FIELDS
     */

    private final Subject owner;
    private final Map<Fingerprint, Subject> subjects;
    private final TrustFileManager fileManager;
    private final String basePath;

    /**
     * Constructor.
     *
     * @param basePath
     * @param owner
     * @throws Exception
     */
    public TrustManager(final String basePath, final PublicKey owner) throws Exception {
        Log.d(TAG, "Initializing TrustManager");

        // initialize fields
        this.basePath = basePath;

        // register owner of the repository (root of trust)
        this.owner = new Subject();
        this.owner.publicKey = owner;
        this.owner.fingerprint = new Fingerprint(owner);
        this.owner.trustInfo.level = TrustLevel.ULTIMATE;
        this.owner.trustInfo.degree = 0;

        try {
            // verify owner
            this.fileManager = TrustFileManager.getInstance(basePath);
            this.fileManager.loadPublicKey(this.owner.fingerprint);

            Signature self = this.fileManager.loadSignature(this.owner.publicKey, this.owner.publicKey);
            this.owner.issued.add(self);
            this.owner.issuers.add(self);
        } catch (Exception e) {
            throw new IllegalArgumentException("Illegal owner! Unable to load corresponding files!", e);
        }

        this.subjects = new HashMap<>();
    }

    // ---- DEDUCTION

    private void reset() {
        this.subjects.clear();
    }

    /**
     * Initializes the trust repository
     * */
    public void initialize() throws Exception {
        this.reset();

        // get trust directory
        final File trustDir = new File(this.basePath, Config.TRUST_PATH);

        if (trustDir.exists() && !trustDir.isDirectory())
            throw new IllegalArgumentException("Illegal trust directory: " + trustDir);

        if (!trustDir.exists())
            trustDir.mkdirs();

        File[] subjects = trustDir.listFiles();
        for (File directory : subjects) {
            if (!directory.isDirectory())
                continue;

            try {
                Fingerprint fingerprint = Fingerprint.fromData(directory.getName());

                Subject subject = this.owner;
                if (!this.owner.fingerprint.equals(fingerprint)) {
                    subject = new Subject();
                    subject.fingerprint = fingerprint;
                    // -> will check fingerprint validity
                    subject.publicKey = this.fileManager.loadPublicKey(fingerprint);

                    // -> will verify self signature
                    Signature self = this.fileManager.loadSignature(subject.publicKey, subject.publicKey);
                    subject.issued.add(self);
                    subject.issuers.add(self);
                }

                // check for self signature + remaining
                this.initializeSignatures(directory, subject);

                this.initializeSubKeys(directory, subject);

                this.subjects.put(fingerprint, subject);
                this.resolveUnboundSignatures(fingerprint);
            } catch (Exception e) {
                Log.e(TAG, "Unable to deduce subject from: " + directory, e);
            }
        }

        this.refreshValidity();
    }

    /**
     * Reads signatures from trust repository
     */
    private void initializeSignatures(File directory, Subject subject) {
        File[] files = directory.listFiles();
        for (File file : files) {
            if (file.isDirectory() || !file.getName().endsWith(".sig"))
                continue;

            try {
                Fingerprint fingerprint = Fingerprint
                        .fromData(file.getName().substring(0, file.getName().length() - 4));

                Signature signature = null;

                // skip self signature
                if (fingerprint.equals(subject.fingerprint))
                    continue;

                // check if issuer is known
                if (this.subjects.containsKey(fingerprint)) {
                    Subject issuer = this.subjects.get(fingerprint);

                    // -> will verify signature
                    signature = this.fileManager.loadSignature(issuer.publicKey, subject.publicKey);

                    issuer.issued.add(signature);
                } else {
                    signature = this.fileManager.loadSignature(fingerprint, subject.fingerprint);
                }

                subject.issuers.add(signature);
            } catch (Exception e) {
                Log.e(TAG, "Unable to deduce signature from: " + file, e);
            }
        }
    }

    /**
     * Reads subkeys from trust repository
     */
    private void initializeSubKeys(File directory, Subject subject) {
        File[] files = new File(directory, "keys/").listFiles();
        for (File file : files) {
            if (file.isDirectory() || !file.getName().endsWith(".sig"))
                continue;

            try {
                KeyID keyID = KeyID.fromData(file.getName().substring(0, file.getName().length() - 4));

                SubKeyEntry subKey = new SubKeyEntry();
                // -> will verify key ID
                subKey.publicKey = this.fileManager.loadPublicSubKey(subject.fingerprint, keyID);
                // -> will verify sub key signature
                subKey.signature = this.fileManager.loadSubKeySignature(subject.publicKey, subKey.publicKey);

                subject.subKeys.put(keyID, subKey);
            } catch (Exception e) {
                Log.e(TAG, "Unable to deduce sub key from: " + file, e);
            }
        }
    }

    // ---- HELPER

    public boolean isInitialized() {
        return this.subjects.size() > 0;
    }

    /**
     * Count all local sub keys registered by the given app (package name)
      */
    private int countLocalSubKeysForApp(AppDetails details) {
        int result = 0;
        for (SubKeyEntry entry : this.owner.subKeys.values()) {
            if (entry.signature.getAppAuthentication().packageName.equals(details.packageName))
                result++;
        }

        return result;
    }

    /**
     * Resolves previously unbound signatures (inserted w/o having a subject in
     * the repository)
     * */
    private boolean resolveUnboundSignatures(Fingerprint fingerprint) {
        if (!this.subjects.containsKey(fingerprint))
            return false;

        Subject issuer = this.subjects.get(fingerprint);

        boolean found = false;

        // check signatures issued for all other subjects
        for (Fingerprint current : this.subjects.keySet()) {
            // skipping myself
            if (current.equals(fingerprint))
                continue;

            Subject subject = this.subjects.get(current);

            Iterator<Signature> iter = subject.issuers.iterator();
            while (iter.hasNext()) {
                Signature signature = iter.next();

                if (!signature.getIssuer().equals(fingerprint))
                    continue;

                // check if unbound, yet
                if (issuer.issued.contains(signature))
                    continue;

                try {
                    // found a signature by the given issuer, validating
                    if (signature.verify(issuer.publicKey, subject.publicKey)) {
                        issuer.issued.add(signature);
                        found = true;
                        continue;
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error verifying signature, skipping", e);
                    continue;
                }

                Log.e(TAG, "An unbound signature, proved to be invalid and is therefore removed!");

                try {
                    this.fileManager.deleteSignature(signature);
                    iter.remove();
                } catch (Exception e) {
                    // swallow
                }
            }
        }

        return found;
    }

    // ---- VALIDITY

    public void refreshValidity() {
        int countChanged;
        boolean deleteIfUnknown = false;
        do {
            // reset counter
            countChanged = 0;

            Queue<Fingerprint> queue = new LinkedList<>();
            queue.add(this.owner.fingerprint);

            Set<Fingerprint> visited = new HashSet<>();
            visited.add(this.owner.fingerprint);

            while (!queue.isEmpty()) {
                Fingerprint current = queue.remove();

                if (!this.subjects.containsKey(current))
                    continue;

                int change = this.checkValidity(current, deleteIfUnknown);

                if (change == -1) // still invalid, skip
                    continue;

                if (change == 1) // increase count changed
                    countChanged++;

                Subject subject = this.subjects.get(current);

                for (Signature signature : subject.issued) {
                    Fingerprint child = signature.getSubject();

                    if (!visited.add(child))
                        continue;

                    queue.add(child);
                }
            }

            if (countChanged == 0 && !deleteIfUnknown) {
                // append one last clean-up round
                countChanged = 1;
                deleteIfUnknown = true;
            }
        } while (countChanged > 0);
    }

    // do this after inserting new subjects (+ their signatures)
    // -1 not valid, 0 valid, 1 valid and changed
    private int checkValidity(Fingerprint fingerprint, boolean deleteIfUnknown) {
        if (!this.subjects.containsKey(fingerprint))
            return -1; // invalid

        if (this.owner.fingerprint.equals(fingerprint))
            return 0; // valid, not changed

        Subject subject = this.subjects.get(fingerprint);

        TrustInfo trustInfo = new TrustInfo();
        trustInfo.level = this.determineTrustLevel(subject);
        trustInfo.degree = this.determineCertificationPath(fingerprint);

        if (trustInfo.degree != -1 && trustInfo.degree <= Config.TRUST_MAX_DEGREE
                && trustInfo.level != TrustLevel.UNKNOWN) {
            if (subject.trustInfo.equals(trustInfo))
                return 0; // valid, not changed

            // update trust info since it changed!
            subject.trustInfo = trustInfo;
            return 1; // valid, changed!!!
        }

        if (!deleteIfUnknown)
            return -1; // invalid

        Log.w(TAG, "Could not prove validity of subject, deleting it! " + trustInfo + ", " + fingerprint);

        // delete entire subject
        this.subjects.remove(fingerprint);
        this.fileManager.deleteSubject(fingerprint);

        // remove signature references (which have just been deleted)
        for (Signature signature : subject.issuers) {
            if (!this.subjects.containsKey(signature.getIssuer()))
                continue;

            Subject issuer = this.subjects.get(signature.getIssuer());
            issuer.issued.remove(signature);
        }

        return -1; // invalid
    }

    public boolean checkValidity(Fingerprint fingerprint) {
        return this.checkValidity(fingerprint, true) >= 0;
    }

    // return if changed
    private TrustLevel determineTrustLevel(Subject subject) {
        // check if subject is already TRUSTED or ULTIMATE
        if (TrustLevel.TRUSTED.compareTo(subject.trustInfo.level) <= 0)
            return subject.trustInfo.level;

        TrustLevel result = TrustLevel.UNKNOWN;

        int k = 0;
        for (Signature signature : subject.issuers) {
            if (!this.subjects.containsKey(signature.getIssuer()))
                continue;

            Subject issuer = this.subjects.get(signature.getIssuer());

            if (issuer.trustInfo.level == TrustLevel.ULTIMATE) // 1x U -> T
                return TrustLevel.TRUSTED;

            if (issuer.trustInfo.level == TrustLevel.TRUSTED) // 1x T -> K
                result = TrustLevel.KNOWN;
            else if (issuer.trustInfo.level == TrustLevel.KNOWN) // 3x K -> K
                k++;

            if (k >= Config.TRUST_NUM_KNOWN_REQUIRED)
                result = TrustLevel.KNOWN;
        }

        return result;
    }

    private int determineCertificationPath(Fingerprint fingerprint) {
        Set<Fingerprint> visited = new HashSet<>();
        Map<Fingerprint, Integer> distances = new HashMap<>();

        Queue<Fingerprint> queue = new LinkedList<>();
        queue.add(fingerprint);

        visited.add(fingerprint);
        distances.put(fingerprint, 0);

        while (!queue.isEmpty()) {
            Fingerprint node = queue.remove();
            int currentDistance = distances.get(node);

            if (this.owner.fingerprint.equals(node))
                return currentDistance;

            if (!this.subjects.containsKey(node))
                continue;

            Subject subject = this.subjects.get(node);

            for (Signature signature : subject.issuers) {
                Fingerprint issuer = signature.getIssuer();
                if (!visited.add(issuer))
                    continue;

                distances.put(issuer, currentDistance + 1);
                queue.add(issuer);
            }
        }

        return -1;
    }

    // ---- DIRECT GETTER

    public PublicKey getPublicKey(Fingerprint fingerprint) {
        if (!this.subjects.containsKey(fingerprint))
            return null;

        return this.subjects.get(fingerprint).publicKey;
    }

    public TrustInfo getTrustInfo(Fingerprint fingerprint) {
        if (!this.subjects.containsKey(fingerprint))
            return TrustInfo.UNKNOWN;

        return this.subjects.get(fingerprint).trustInfo;
    }

    /**
     *  the appDetails argument is expected to have both PN, and SK set by the service
     * */
    public byte[] getSubKey(Fingerprint fingerprint, KeyID keyID, AppDetails appDetails) {
        if (!this.subjects.containsKey(fingerprint))
            return null;

        Subject subject = this.subjects.get(fingerprint);

        // check if requested sub key is available
        if (!subject.subKeys.containsKey(keyID))
            return null;

        SubKeyEntry subKey = subject.subKeys.get(keyID);

        // check app authorization (if required)
        if (!subKey.signature.getAppAuthentication().allowsFor(appDetails))
            return null;

        return subKey.publicKey;
    }

    /**
     * Get all SubKeys for the given subject and (optionally) for the given
     * description. If no description is given, all available subkeys will be
     * returned. If a description is given, only the subkeys containing the tag
     * will be returned.
     */
    public Set<KeyID> getAvailableSubKeys(Fingerprint fingerprint, AppDetails authDetails, String tag) {
        if (!this.subjects.containsKey(fingerprint))
            return null;

        Subject subject = this.subjects.get(fingerprint);

        Set<KeyID> result = new HashSet<>();

        for (KeyID keyID : subject.subKeys.keySet()) {
            SubKeyEntry subKey = subject.subKeys.get(keyID);
            SubKeySignature signature = subKey.signature;

            // check if app has the permissions to access subkey
            if (!signature.getAppAuthentication().allowsFor(authDetails))
                continue;

            String sTag = signature.getTag();
            if (sTag == null && tag != null)
                continue;

            if (sTag != null && tag != null && !sTag.toLowerCase().contains(tag.toLowerCase()))
                continue;

            result.add(signature.getSubKey());
        }

        return result;
    }

    // owner is included
    public Set<Fingerprint> getSubjectsWithTrustLevel(TrustLevel level) {
        if (level == TrustLevel.KNOWN)
            return new HashSet<>(this.subjects.keySet());

        Set<Fingerprint> result = new HashSet<Fingerprint>();
        if (level == TrustLevel.UNKNOWN)
            return result;

        for (Fingerprint current : this.subjects.keySet()) {
            Subject subject = this.subjects.get(current);

            if (level.compareTo(subject.trustInfo.level) > 0)
                continue;

            result.add(current);
        }

        return result;
    }

    /**
     * Returns all data related to a set of knowing subjects
     * */
    public Set<Serializable> getRelatedData(Set<Fingerprint> trustedSubjects) {
        Set<Serializable> result = new HashSet<Serializable>();

        // get all signatures arbitrary -> trustedSubjects
        // get all signatures trustedSubjects <- trustedSubjects (at least
        // subject must be known!)
        // -> actually 2nd line is included in first statement!!
        // however was ist mit neuen related public keys v oben?
        for (Fingerprint current : trustedSubjects) {
            // check if information about the subject are available
            if (!this.subjects.containsKey(current))
                continue;

            // all public keys that have been signed by the trusted subjects
            // (except the ones that he already has)
            Subject issuer = this.subjects.get(current);

            // add all arbitrary signatures issued on trusted subject (update)
            result.addAll(issuer.issuers);

            // add all known sub keys for trusted subject (update)
            result.addAll(issuer.subKeys.values());

            for (Signature issued : issuer.issued) {
                // if (result.contains(issued))
                // eigentlich überflüssig
                if (trustedSubjects.contains(issued.getSubject()))
                    continue;

                // trustedsubject (issuer) -> subject
                Subject subject = this.subjects.get(issued.getSubject());
                result.add(subject.publicKey);

                // add all signatures towards this new subject (extend)
                result.addAll(subject.issuers);
                result.addAll(subject.subKeys.values());
            }
        }

        return result;
    }

    public MetaInformation getMetaInformation(Fingerprint fingerprint) {
        if (!this.subjects.containsKey(fingerprint))
            return null;

        Subject subject = this.subjects.get(fingerprint);

        MetaInformation result = new MetaInformation();

        // fill in aliases
        @SuppressWarnings("unchecked")
        List<String>[] priorities = new List[Config.TRUST_MAX_DEGREE + 2];
        Arrays.fill(priorities, null);

        for (Signature signature : subject.issuers) {
            if (signature.getAlias() == null)
                continue;

            // determine priority by checking issuer degree
            int i = Config.TRUST_MAX_DEGREE + 1;
            if (this.subjects.containsKey(signature.getIssuer())) {
                Subject issuer = this.subjects.get(signature.getIssuer());
                i = issuer.trustInfo.degree;
            }
            System.out.println("Adding " + signature.getAlias() + " @ " + i);

            if (priorities[i] == null)
                priorities[i] = new ArrayList<>();

            priorities[i].add(signature.getAlias());
        }

        List<String> aliases = new ArrayList<>();
        Set<String> doubles = new HashSet<>();
        for (int i = 0; i < Config.TRUST_MAX_DEGREE + 2; i++) {
            if (doubles.size() > Config.TRUST_MAX_META_ALIASES)
                break;

            if (priorities[i] == null)
                continue;

            for (String alias : priorities[i]) {
                if (doubles.size() > Config.TRUST_MAX_META_ALIASES)
                    break;

                if (!doubles.add(alias))
                    continue;

                aliases.add(alias);
            }
        }

        result.put(MetaInformation.META_ALIASES, aliases);

        // add timestamp of the last synchronization w/ subject
        result.put(MetaInformation.META_LAST_SYNC, subject.lastSynchronization);

        return result;
    }

    /**
     * Trying to insert a new subject to repository
     * assume valid (signature checked w/ the given public key)
     * */
    public boolean addSubject(PublicKey publicKey, Signature self) throws Exception {
        if (publicKey == null || self == null)
            throw new IllegalArgumentException();

        Fingerprint fingerprint = self.getSubject();

        // check if already exists
        if (this.subjects.containsKey(fingerprint))
            return false;

        Log.d(TAG, "Adding a new subject to repository: " + self.getSubject());

        // create new entry
        Subject node = new Subject();
        node.fingerprint = fingerprint;
        node.publicKey = publicKey;
        node.issuers.add(self);
        node.issued.add(self);

        // persistently store public key
        if (!this.fileManager.savePublicKey(publicKey, self)) {
            Log.e(TAG, "- Fatal error: This line should not be reached! (see Deduction for possible bug!)");
            return false;
        }

        this.subjects.put(fingerprint, node);

        if (this.resolveUnboundSignatures(fingerprint))
            Log.d(TAG, "- Unbound signatures have successfully been resolved!");

        return true;
    }

    /**
     * Trying to insert a new signature to repository (assume its valid)
     * returns true if inserted, false if subject could not be found
     * options:
     * - both subject and issuer known -> insert
     * - only subject known -> insert (validate when issuer becomes known)
     * - only issuer known -> subject should be known due to sync! => dropped
     * */
    public boolean addSignature(Signature signature) throws Exception {
        if (signature == null)
            throw new IllegalArgumentException();

        if (!this.subjects.containsKey(signature.getSubject()))
            return false;

        // persistently store signature (return if already have this signature)
        if (!this.fileManager.saveSignature(signature))
            return false;

        Log.d(TAG, "Adding a new signature to repository");

        Subject subject = this.subjects.get(signature.getSubject());
        subject.issuers.add(signature);

        // when issuer not yet known to the device
        if (!this.subjects.containsKey(signature.getIssuer()))
            return true;

        // both are known
        Subject issuer = this.subjects.get(signature.getIssuer());
        issuer.issued.add(signature);

        return true;
    }

    /**
     * Adds a new sub-key to the trust-repository
     * */
    public boolean addSubKey(byte[] publicSubKey, SubKeySignature signature) throws Exception {
        if (publicSubKey == null || signature == null)
            throw new IllegalArgumentException();

        if (!this.subjects.containsKey(signature.getOwner()))
            return false;

        Log.d(TAG, "Adding a new sub key to the repository");

        Subject subject = this.subjects.get(signature.getOwner());

        // check if this is a local sub-key
        if (this.owner.fingerprint.equals(signature.getOwner())) {
            if (this.countLocalSubKeysForApp(signature.getAppAuthentication()) > Config.TRUST_MAX_SUB_KEY_PER_APP) {
                Log.w(TAG, "App already has reached the maximum allowed number of sub keys registered!");
                return false;
            }
        }

        // persistently store sub-key & signature
        this.fileManager.saveSubKey(publicSubKey, signature);

        SubKeyEntry entry = new SubKeyEntry();
        entry.publicKey = publicSubKey;
        entry.signature = signature;

        subject.subKeys.put(signature.getSubKey(), entry);

        return true;
    }

    /**
     * Updates the last synchronization time for a given fingerprint
     * */
    public boolean updateLastSynchronization(Fingerprint fingerprint) {
        if (!this.subjects.containsKey(fingerprint))
            return false;

        Subject subject = this.subjects.get(fingerprint);

        subject.lastSynchronization = System.currentTimeMillis();

        return true;
    }

    public long getLastSynchronization(Fingerprint fingerprint) {
        if (!this.subjects.containsKey(fingerprint))
            return -1;

        Subject subject = this.subjects.get(fingerprint);

        return subject.lastSynchronization;
    }
}
