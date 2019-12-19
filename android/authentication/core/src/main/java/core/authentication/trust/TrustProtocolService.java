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

import core.authentication.exceptions.NetworkException;
import core.authentication.network.Network;
import core.authentication.network.messages.HandshakeInitializeMessage;
import core.authentication.network.messages.HandshakeSignatureMessage;
import core.authentication.network.messages.SyncMessage;
import core.authentication.network.messages.SyncRequestMessage;
import core.authentication.trust.entries.SubKeyEntry;
import keyverifier.KeyVerifierActivity;
import network.NetworkConnection;
import network.messages.Message;
import primitives.config.Config;
import primitives.keys.Fingerprint;
import primitives.keys.Signature;
import primitives.trust.TrustInfo;
import primitives.trust.TrustLevel;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TrustProtocolService class implements both trust protocols: handshake and synchronization
 *
 *@author Max Kolhagen
 */
public class TrustProtocolService extends Service implements Network.NetworkListener, NetworkConnection.SenderCallback {

    // Constants for logging
    private static final String TAG = TrustProtocolService.class.getSimpleName();
    private static final String PACKAGE = TrustProtocolService.class.getPackage().getName();

    private static final String ACTION_HANDSHAKE_START = PACKAGE + ".action.HANDSHAKE";
    private static final String ACTION_KEYVERIFY_FINISH = PACKAGE + ".action.KEYVERIFY_FINISH";

    // Constants for broadcast
    private static final String ACTION_HANDSHAKE_FINISHED = PACKAGE + ".action.HANDSHAKE_FINISHED";
    private static final String ACTION_HANDSHAKE_ERROR = PACKAGE + ".action.HANDSHAKE_ERROR";

    private static final String EXTRA_PARTNER = PACKAGE + ".extra.PARTNER";
    private static final String EXTRA_RESULT = PACKAGE + ".extra.RESULT";
    private static final String EXTRA_ERROR = PACKAGE + ".extra.ERROR";

    /**
     * Wrapper class for caching handshake information.
     */
    public static class HandshakeCacheItem {
        public HandshakeInitializeMessage message = null;
        public Signature signature = null;
        public Signature signatureRemote = null;
        public final long started = System.currentTimeMillis();
    }

    /**
     * FIELDS
     */
    private Object MUTEX_TRUST_MANAGER = new Object();
    private Map<Fingerprint, HandshakeCacheItem> handshakeCache = new ConcurrentHashMap<>();

    private Network network = null;
    private ManagerService.Managers managers = null;

    @Override
    public void onCreate() {
        super.onCreate();

        this.checkManagers();

        try {
            // initialize the network connection (incoming)
            this.network = new Network(this, this);
        } catch (Exception e) {
            Log.e(TAG, "Fatal Error: Could not initialize network!");
        }
    }

    /**
     * Check for the availability of both managers.
     *
     * @return
     */
    private boolean checkManagers() {
        this.managers = ManagerService.Managers.getInstance();
        if (this.managers != null && this.managers.isInitialized())
            return true;

        // if not, request them...
        Intent intent = new Intent(this, TrustProtocolService.class);
        intent.setAction(ManagerService.ACTION_GET_MANAGERS);
        PendingIntent pending = PendingIntent.getService(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
        ManagerService.requestManagers(this, pending);
        return false;
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // -- SERVICE

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);

        Log.d(TAG, "onStartCommand - " + intent);

        final String action = intent.getAction();

        if (!this.checkManagers()) {
            Log.e(TAG, "No managers available yet, please wait...");
            return Service.START_STICKY;
        }

        // dispatch incoming intents
        if (ACTION_HANDSHAKE_START.equals(action)) {
            final Fingerprint partner = (Fingerprint) intent.getSerializableExtra(EXTRA_PARTNER);
            this.onPerformHandshake(partner);
        } else if (ACTION_KEYVERIFY_FINISH.equals(action)) {
            final Fingerprint partner = (Fingerprint) intent.getSerializableExtra(KeyVerifierActivity.EXTRA_PARTNER);
            final int code = intent.getIntExtra(KeyVerifierActivity.EXTRA_CODE, KeyVerifierActivity.RESULT_ERROR);
            if (code == KeyVerifierActivity.RESULT_ERROR) {
                final Throwable error = (Throwable) intent.getSerializableExtra(KeyVerifierActivity.EXTRA_ERROR);
                this.onKeyVerificationError(partner, error);
            } else {
                final boolean result = intent.getBooleanExtra(KeyVerifierActivity.EXTRA_RESULT, false);
                final String alias = intent.getStringExtra(KeyVerifierActivity.EXTRA_ALIAS);
                this.onKeyVerificationFinished(partner, alias, result);
            }
        }

        return Service.START_STICKY;
    }

    /**
     * Static method to start performing a handshake with the given fingerprint.
     *
     * @param context
     * @param partner
     */
    public static void performHandshake(Context context, Fingerprint partner) {
        Intent intent = new Intent(context, TrustProtocolService.class);
        intent.setAction(ACTION_HANDSHAKE_START);
        intent.putExtra(EXTRA_PARTNER, partner);
        context.startService(intent);
    }

    // -- NETWORK

    @Override
    public void onMessageReceived(Fingerprint fingerprint, Message message) {
        if (!this.checkManagers()) {
            Log.e(TAG, "No managers available yet, please wait...");
            return;
        }

        // dispatch incoming network messages
        switch (message.getType()) {
            case SyncRequestMessage.TYPE_SYNC_REQUEST:
                this.onSyncRequestMessageReceived(fingerprint, (SyncRequestMessage) message);
                break;
            case SyncMessage.TYPE_SYNC:
                this.onSyncMessageReceived(fingerprint, (SyncMessage) message);
                break;
            case HandshakeInitializeMessage.TYPE_HANDSHAKE_INIT:
                this.onHandshakeInitializeMessageReceived(fingerprint, (HandshakeInitializeMessage) message);
                break;
            case HandshakeSignatureMessage.TYPE_HANDSHAKE_SIGNATURE:
                this.onHandshakeSignatureMessageReceived(fingerprint, (HandshakeSignatureMessage) message);
                break;
            default:
                Log.w(TAG, "Received an unknown message of type: " + message.getType());
        }
    }

    @Override
    public void onSuccess() {
        Log.d(TAG, "Successfully sent message.");
    }

    @Override
    public void onFailure(Exception e) {
        Log.e(TAG, "Error sending message!", e);
    }

    // -- BROADCAST

    public enum BroadcastType {
        HANDSHAKE, SYNCHRONIZATION;
    }

    private void broadcastProtocolFinish(BroadcastType type, Fingerprint fingerprint, boolean result) {
        Intent intent = new Intent(ACTION_HANDSHAKE_FINISHED); // TODO: anpassen type
        intent.putExtra(EXTRA_PARTNER, fingerprint);
        intent.putExtra(EXTRA_RESULT, result);
        this.sendBroadcast(intent);
    }

    private void broadcastProtocolError(BroadcastType type, Fingerprint fingerprint, Throwable error) {
        Intent intent = new Intent(ACTION_HANDSHAKE_ERROR);
        intent.putExtra(EXTRA_PARTNER, fingerprint);
        intent.putExtra(EXTRA_ERROR, error);
        this.sendBroadcast(intent);
    }

    // -- SYNCHRONIZATION PROTOCOL

    @Override
    public void onPeerListChanged(Set<Fingerprint> neighbors) {
        Log.d(TAG, "Peer list changed - size = " + neighbors.size());

        if (!this.checkManagers()) {
            Log.e(TAG, "No managers available yet, please wait...");
            return;
        }

        final Set<Fingerprint> trustedSubjects;
        synchronized (MUTEX_TRUST_MANAGER) {
            trustedSubjects = this.managers.getTrustManager().getSubjectsWithTrustLevel(TrustLevel.KNOWN);
        }

        for (Fingerprint current : neighbors) {
             try {
                Log.d(TAG, "- Triggering update mechanism for " + current);
                SyncRequestMessage request = new SyncRequestMessage(trustedSubjects);
                Network.send(current, request, this);
            } catch (Exception e) {
                Log.e(TAG, "- Could not send update request!", e);
            }
        }
    }

    private void onPerformSynchronization(Fingerprint fingerprint) {
        Log.d(TAG, "(SY) onPerformSynchronization - " + fingerprint);

        try {
            Set<Fingerprint> trustedSubjects;
            synchronized (MUTEX_TRUST_MANAGER) {
                trustedSubjects = this.managers.getTrustManager().getSubjectsWithTrustLevel(TrustLevel.KNOWN);
            }
            Message send = new SyncRequestMessage(trustedSubjects);
            Network.send(fingerprint, send, this);
        } catch (NetworkException e) {
            Log.e(TAG, "(SY) Could not send update message!", e);
            this.broadcastProtocolError(BroadcastType.SYNCHRONIZATION, fingerprint, e);
            // TODO: also broadcast success for synchronization that has
            // manually been performed?
        }
    }

    private void onSyncRequestMessageReceived(final Fingerprint fingerprint, final SyncRequestMessage message) {
        try {
            Log.d(TAG, "(SY) Received SyncRequestMessage from " + fingerprint);

            Log.d(TAG, "(SY) - Obtaining all related signatures and public keys to the requested subjects");
            final Set<Fingerprint> trustedSubjects = message.getTrustedSubjects();
            Set<Serializable> relatedData;
            synchronized (MUTEX_TRUST_MANAGER) {
                relatedData = this.managers.getTrustManager().getRelatedData(trustedSubjects);
            }

            if (relatedData.size() == 0) {
                Log.d(TAG, "(SY) - Does not have any relevant data, skipping sending sync message!");
                return;
            }

            Log.d(TAG, "(SY) - Send update response");
            Message send = new SyncMessage(relatedData);
            Network.send(fingerprint, send, this);
        } catch (NetworkException e) {
            Log.e(TAG, "(SY) - Could not send update message!", e);
        }
    }

    private void onSyncMessageReceived(final Fingerprint fingerprint, final SyncMessage message) {
        Log.d(TAG, "(SY) Received SyncMessage from " + fingerprint);

        final Set<Serializable> relatedData = message.getRelatedData();

        // initialize counts
        int cSignatures = 0;
        int cPublicKeys = 0;
        int cSubKeys = 0;

        // [sender] assess received related data
        Iterator<Serializable> iterator;

        Log.d(TAG, "(SY) - Extract all self signatures");
        Map<Fingerprint, Signature> selfSignatures = new HashMap<>();
        for (iterator = relatedData.iterator(); iterator.hasNext(); ) {
            Serializable object = iterator.next();
            if (!(object instanceof Signature))
                continue;

            Signature signature = (Signature) object;

            try {
                // is self-signature?
                if (!signature.getIssuer().equals(signature.getSubject()))
                    continue;

                selfSignatures.put(signature.getSubject(), signature);
                iterator.remove();
            } catch (Exception e) {
                Log.e(TAG, "(SY) - Error extracting self-signatures! " + signature, e);
            }
        }

        synchronized (MUTEX_TRUST_MANAGER) {
            Log.d(TAG, "(SY) - Extract all new subjects");
            for (iterator = relatedData.iterator(); iterator.hasNext(); ) {
                Serializable object = iterator.next();
                if (!(object instanceof PublicKey))
                    continue;

                PublicKey publicKey = (PublicKey) object;

                iterator.remove();

                try {
                    // derive fingerprint from public key
                    Fingerprint subject = new Fingerprint(publicKey);

                    TrustInfo info = this.managers.getTrustManager().getTrustInfo(subject);
                    if (!info.equals(TrustInfo.UNKNOWN)) {
                        Log.w(TAG, "(SY) Subject is already known, skipping...");
                        continue;
                    }

                    // check for self signature & verify it
                    Signature signature = selfSignatures.get(subject);

                    if (!signature.verify(publicKey, publicKey))
                        throw new SecurityException("Invalid signature! " + subject);

                    // check if it is a new subject
                    if (this.managers.getTrustManager().addSubject(publicKey, signature)) {
                        cPublicKeys++;
                        cSignatures++;
                    }
                } catch (Exception e) {
                    Log.e(TAG, "(SY) - Error extracting subject!", e);
                }
            }

            Log.d(TAG, "(SY) - Extracting all remaining signatures...");
            for (iterator = relatedData.iterator(); iterator.hasNext(); ) {
                Serializable object = iterator.next();
                if (!(object instanceof Signature))
                    continue;

                Signature signature = (Signature) object;

                iterator.remove();

                try {
                    PublicKey subject = this.managers.getTrustManager().getPublicKey(signature.getSubject());
                    if (subject == null)
                        throw new IllegalArgumentException("Could not find subject!");

                    // verify signature if issuer is known
                    PublicKey issuer = this.managers.getTrustManager().getPublicKey(signature.getIssuer());
                    if (issuer != null && !signature.verify(issuer, subject))
                        throw new SecurityException("Invalid signature!");

                    // signature valid || issuer = null
                    if (this.managers.getTrustManager().addSignature(signature)) {
                        cSignatures++;
                    }
                } catch (Exception e) {
                    Log.e(TAG, "(SY) - Unable to extract signature! " + signature, e);
                }
            }

            Log.d(TAG, "(SY) - Adding new sub keys to repository");
            for (iterator = relatedData.iterator(); iterator.hasNext(); ) {
                Serializable object = iterator.next();
                if (!(object instanceof SubKeyEntry))
                    continue;

                SubKeyEntry subKey = (SubKeyEntry) object;

                iterator.remove();

                try {
                    if (this.managers.getTrustManager().addSubKey(subKey.publicKey, subKey.signature))
                        cSubKeys++;
                } catch (Exception e) {
                    Log.e(TAG, "(SY) - Error extracting sub key! " + subKey, e);
                }
            }

            // if (cSignatures > 0) {
            Log.d(TAG, "(SY) - Verify all newly added subjects & signatures");
            this.managers.getTrustManager().refreshValidity();
            // }

            this.managers.getTrustManager().updateLastSynchronization(fingerprint);
        }

        if (relatedData.size() > 0) {
            Log.w(TAG, "(SY) - Not all related data entries could be processed! " + relatedData.size());
        }

        Log.d(TAG, "(SY) - Summary: " + cPublicKeys + ", " + cSignatures + ", " + cSubKeys);
    }

    // -- HANDSHAKE PROTOCOL

    @SuppressWarnings({"rawtypes", "unchecked"})
    private synchronized boolean isHandshakeRunning(Fingerprint fingerprint) {
        long now = System.currentTimeMillis();
        Iterator iterator = this.handshakeCache.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<Fingerprint, HandshakeCacheItem> entry = (Map.Entry) iterator.next();
            long started = entry.getValue().started;

            if ((now - started) < Config.TRUST_HANDSHAKE_TIMEOUT) {
                // is this the one we are looking for?
                if (entry.getKey().equals(fingerprint))
                    return true;

                continue;
            }

            // clean up fingerprints that timed out (plus cache)
            iterator.remove();
        }

        this.handshakeCache.put(fingerprint, new HandshakeCacheItem());
        return false;
    }

    public void onPerformHandshake(Fingerprint fingerprint) {
        // not checking if there is one going on currently! since user can
        // receive multiple notification popups!
        Log.d(TAG, "(HS) Performing handshake w/ " + fingerprint);

        try {
            // check if for that same fingerprint, already a handshake is going
            // on
            if (this.isHandshakeRunning(fingerprint))
                throw new IllegalArgumentException("Currently already performing a handshake with that fingerprint!");

            // check trust info of subject
            TrustInfo info;
            synchronized (MUTEX_TRUST_MANAGER) {
                info = this.managers.getTrustManager().getTrustInfo(fingerprint);
            }
            if (TrustLevel.TRUSTED.compareTo(info.level) <= 0) {
                Log.d(TAG, "(HS) Subject is already trusted!");
                this.handshakeCache.remove(fingerprint);
                this.broadcastProtocolFinish(BroadcastType.HANDSHAKE, fingerprint, true);
                return;
            }

            // request certificate, send my certificate
            HandshakeInitializeMessage send = new HandshakeInitializeMessage(this.managers.getKeyManager().getPublicKey(),
                    this.managers.getKeyManager().getSignature());

            Network.send(fingerprint, send, this);
        } catch (Exception e) {
            this.handshakeCache.remove(fingerprint);
            this.broadcastProtocolError(BroadcastType.HANDSHAKE, fingerprint, e);
        }
    }

    private void onHandshakeInitializeMessageReceived(final Fingerprint fingerprint,
                                                      final HandshakeInitializeMessage message) {
        Log.d(TAG, "(HS) Received HandshakeInitializeMessage from " + fingerprint);

        try {
            // check if for that same fingerprint, already a handshake is going
            // on (if it was initiated by the other party)
            if (!message.isResponse() && this.isHandshakeRunning(fingerprint))
                throw new IllegalArgumentException("Already performing handshake with the same fingerprint");

            // verify certificate
            Log.d(TAG, "(HS) - Verifying received self-signature");
            if (!message.getSignature().verify(message.getPublicKey(), message.getPublicKey()))
                throw new SignatureException("Received and invalid self-signature!");

            // check if this handshake was initialized by me (if not send
            // response)
            if (!message.isResponse()) {
                // check if already trusted
                TrustInfo info;
                synchronized (MUTEX_TRUST_MANAGER) {
                    info = this.managers.getTrustManager().getTrustInfo(fingerprint);
                }
                if (TrustLevel.TRUSTED.compareTo(info.level) <= 0) {
                    Log.d(TAG, "(HS) Subject is already trusted!");
                    this.handshakeCache.remove(fingerprint);
                    this.broadcastProtocolFinish(BroadcastType.HANDSHAKE, fingerprint, true);
                    return;
                }

                Log.d(TAG, "(HS) - Sending response...");
                HandshakeInitializeMessage send = new HandshakeInitializeMessage(this.managers.getKeyManager().getPublicKey(),
                        this.managers.getKeyManager().getSignature());
                send.setResponse(true);
                Network.send(fingerprint, send, this);
            }

            Log.d(TAG, "(HS) - Verifying public key over a secure channel...");

            HandshakeCacheItem cache = this.handshakeCache.get(fingerprint);
            cache.message = message;

            Intent intent = new Intent(this, TrustProtocolService.class);
            intent.setAction(ACTION_KEYVERIFY_FINISH);
            PendingIntent result = PendingIntent.getService(this, 0, intent, 0);
            KeyVerifierActivity.showNotification(this, this.managers.getKeyManager().getPublicKey(), cache.message.getPublicKey(), cache.message.getSignature(), result);
        } catch (Exception e) {
            this.handshakeCache.remove(fingerprint);
            this.broadcastProtocolError(BroadcastType.HANDSHAKE, fingerprint, e);
        }
    }

    private void onKeyVerificationError(Fingerprint partner, Throwable error) {
        Log.e(TAG, "(HS) onKeyVerificationError - " + partner, error);

        this.handshakeCache.remove(partner);

        this.broadcastProtocolError(BroadcastType.HANDSHAKE, partner, error);
    }

    private void onKeyVerificationFinished(Fingerprint partner, String alias, boolean result) {
        Log.d(TAG, "(HS) onKeyVerificationFinished - " + partner + ", " + alias + ", " + result);

        if (!result) {
            this.handshakeCache.remove(partner);
            this.broadcastProtocolFinish(BroadcastType.HANDSHAKE, partner, false);
            return;
        }

        try {
            // check cache
            if (!this.handshakeCache.containsKey(partner))
                throw new IllegalStateException("HandshakeInitializeMessage was not cached! Too long ago?");

            HandshakeCacheItem cache = this.handshakeCache.get(partner);

            // sign other public key and add signature
            cache.signature = this.managers.getKeyManager().createSignature(cache.message.getPublicKey(), alias);

            // send my new signature
            Log.d(TAG, "(HS) - Sending HandshakeSignatureMessage response");
            Message send = new HandshakeSignatureMessage(cache.signature);
            Network.send(partner, send, this);

            this.checkHandshakeComplete(partner);
        } catch (Exception e) {
            this.handshakeCache.remove(partner);
            this.broadcastProtocolError(BroadcastType.HANDSHAKE, partner, e);
        }
    }

    private void onHandshakeSignatureMessageReceived(final Fingerprint fingerprint,
                                                     final HandshakeSignatureMessage message) {
        Log.d(TAG, "(HS) Received HandshakeSignatureMessage from " + fingerprint);

        try {
            // check cache
            if (!this.handshakeCache.containsKey(fingerprint))
                throw new IllegalStateException("HandshakeInitializeMessage was not cached! Too long ago?");

            HandshakeCacheItem cache = this.handshakeCache.get(fingerprint);

            Log.d(TAG, "(HS) - Verifying received signature");
            Signature signature = message.getSignature();
            if (!signature.verify(cache.message.getPublicKey(), this.managers.getKeyManager().getPublicKey()))
                throw new SignatureException("Received signature is invalid!");

            cache.signatureRemote = signature;

            this.checkHandshakeComplete(fingerprint);
        } catch (Exception e) {
            // this.managers.getTrustManager().checkValidity(fingerprint);
            this.handshakeCache.remove(fingerprint);
            this.broadcastProtocolError(BroadcastType.HANDSHAKE, fingerprint, e);
        }
    }

    private synchronized void checkHandshakeComplete(final Fingerprint fingerprint) throws Exception {
        if (!this.handshakeCache.containsKey(fingerprint))
            return;

        HandshakeCacheItem cache = this.handshakeCache.get(fingerprint);

        // check if required data is present yet
        if (cache.message == null || cache.signature == null || cache.signatureRemote == null)
            return;

        synchronized (MUTEX_TRUST_MANAGER) {
            // add subject
            if (!this.managers.getTrustManager().addSubject(cache.message.getPublicKey(), cache.message.getSignature())) {
                TrustInfo info = this.managers.getTrustManager().getTrustInfo(fingerprint);
                if (info.level == TrustLevel.TRUSTED) {
                    Log.w(TAG, "(HS) Somehow this subject managed to become trusted!?!");
                } else if (info.level == TrustLevel.UNKNOWN) {
                    throw new IllegalStateException(
                            "Unable to add subject to repository! However, still is UNKNOWN (Inconsistency?) "
                                    + fingerprint);
                }
            }

            // my signature
            Log.d(TAG, "(HS) - Add my signature to TrustManager");
            this.managers.getTrustManager().addSignature(cache.signature);

            // remote signature
            Log.d(TAG, "(HS) - Add remote signature to TrustManager");
            this.managers.getTrustManager().addSignature(cache.signatureRemote);

            Log.d(TAG, "(HS) - Check validity of new subject");
            if (!this.managers.getTrustManager().checkValidity(fingerprint))
                throw new IllegalStateException("Could not validate the trust from the new subject!");
        }

        this.handshakeCache.remove(fingerprint);
        this.broadcastProtocolFinish(BroadcastType.HANDSHAKE, fingerprint, true);

        Log.d(TAG, "(HS) - Triggering update mechanism");
        this.onPerformSynchronization(fingerprint);
    }
}
