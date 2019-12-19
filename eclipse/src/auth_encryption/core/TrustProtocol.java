package auth_encryption.core;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import auth_encryption.log.Log;
import auth_encryption.primitives.Config;
import auth_encryption.primitives.Fingerprint;
import auth_encryption.primitives.Signature;
import auth_encryption.primitives.TrustInfo;
import auth_encryption.primitives.TrustLevel;
import auth_encryption.simulator.DeviceLog;
import core.DTNHost;
import core.SimScenario;

public abstract class TrustProtocol {
	private String TAG = TrustProtocol.class.getSimpleName();

	public static class HandshakeCacheItem {
		public HandshakeInitializeMessage message = null;
		public Signature signature = null;
		public Signature signatureRemote = null;
		public final long started = System.currentTimeMillis();
	}

	private Object MUTEX_TRUST_MANAGER = new Object();

	protected final KeyManager keyManager;
	protected TrustManager trustManager;

	private Map<Fingerprint, HandshakeCacheItem> handshakeCache = new ConcurrentHashMap<>();

	protected TrustProtocol(final KeyManager keyManager, final String basePath) throws Exception {
		Log.d(TAG, "Initializing TrustProtocol");

		this.TAG += "/" + basePath.substring(basePath.length() - 4, basePath.length());

		this.keyManager = keyManager;
		this.trustManager = new TrustManager(basePath, keyManager.getPublicKey());
		this.trustManager.initialize();
	}

	// -- SYNCHRONIZATION PROTOCOL

	public void onPeerListChanged(List<Fingerprint> neighbors) {
		
		////////////////////////////////////////////////////
		Log.d(TAG, "############################");
		Log.d(TAG, "Peer list changed - size = " + neighbors.size());
		////////////////////////////////////////////////////
		
		final Set<Fingerprint> trustedSubjects;
		synchronized (MUTEX_TRUST_MANAGER) {
			trustedSubjects = this.trustManager.getSubjectsWithTrustLevel(TrustLevel.KNOWN);
		}

		// long now = System.currentTimeMillis();
		for (Fingerprint current : neighbors) {
			// synchronized (MUTEX_TRUST_MANAGER) {
			// long lastSync =
			// this.trustManager.getLastSynchronization(current);
			// if ((now - lastSync) < Config.TRUST_TRIGGER_UPDATE_INTERVAL) {
			// Log.d(TAG, "- Skipping " + current);
			// continue;
			// }
			// }

			try {
				//Log.d(TAG, "- Triggering update mechanism for " + current);
				SyncRequestMessage request = new SyncRequestMessage(trustedSubjects, getHostByFingerprint(current));
				//////////////////////////
				request.setSizeSerializable(getHostByFingerprint(current));
				//Log.d(TAG, "- Triggering update mechanism for device: " + request.getFrom());
				//////////////////////////
				this.send(current, request);
			} catch (Exception e) {
				Log.e(TAG, "- Could not send update request!", e);
			}
		}
	}

	private void onPerformSynchronization(Fingerprint fingerprint) {
		
		//Log.d(TAG, "(SY) onPerformSynchronization - " + fingerprint);
		
		try {
			Set<Fingerprint> trustedSubjects;
			synchronized (MUTEX_TRUST_MANAGER) {
				trustedSubjects = this.trustManager.getSubjectsWithTrustLevel(TrustLevel.KNOWN);
			}
			MessageAuthentication send = new SyncRequestMessage(trustedSubjects, getHostByFingerprint(fingerprint));
			//////////////////////////
			send.setSizeSerializable(getHostByFingerprint(fingerprint));
			//Log.d(TAG, "(SY) onPerformSynchronization for device: " + send.getFrom());
			//////////////////////////
			this.send(fingerprint, send);
		} catch (NetworkException e) {
			Log.e(TAG, "(SY) Could not send update message!", e);
			this.broadcastProtocolError(BroadcastType.SYNCHRONIZATION, fingerprint, e);
			// TODO: also broadcast success for synchronization that has
			// manually been performed?
		}
	}

	private void onSyncRequestMessageReceived(final Fingerprint fingerprint, final SyncRequestMessage message) {
		try {			
			///////////////////////////////////////////////////////////////////
			//Log.d(TAG, "(SY) Received SyncRequestMessage from " + fingerprint);		
		
			//Log.d(TAG, "(SY) - Obtaining all related signatures and public keys to the requested subjects");
			///////////////////////////////////////////////////////////////////
			final Set<Fingerprint> trustedSubjects = message.getTrustedSubjects();
			Set<Serializable> relatedData;
			synchronized (MUTEX_TRUST_MANAGER) {
				relatedData = this.trustManager.getRelatedData(trustedSubjects);
			}

			if (relatedData.size() == 0) {
				Log.d(TAG, "(SY) - Does not have any relevant data, skipping sending sync message!");
				return;
			}

			//Log.d(TAG, "(SY) - Send update response");
			MessageAuthentication send = new SyncMessage(relatedData, getHostByFingerprint(fingerprint));
			//////////////////////////
			send.setSizeSerializable(getHostByFingerprint(fingerprint));
			//Log.d(TAG, "(SY) - Send update response for device: " + send.getFrom());
			//////////////////////////
			this.send(fingerprint, send);
		} catch (NetworkException e) {
			Log.e(TAG, "(SY) - Could not send update message!", e);
		}
	}

	private void onSyncMessageReceived(final Fingerprint fingerprint, final SyncMessage message) {
		
		Log.d(TAG, "(SY) Received SyncMessage from " + fingerprint);
		///////////////////////////////////////////////////////////////////
		
		final Set<Serializable> relatedData = message.getRelatedData();

		// initialize counts
		int cSignatures = 0;
		int cPublicKeys = 0;
		int cSubKeys = 0;

		// [sender] assess received related data
		Iterator<Serializable> iterator;

		//Log.d(TAG, "(SY) - Extract all self signatures");
		Map<Fingerprint, Signature> selfSignatures = new HashMap<>();
		for (iterator = relatedData.iterator(); iterator.hasNext();) {
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
			//Log.d(TAG, "(SY) - Extract all new subjects");
			for (iterator = relatedData.iterator(); iterator.hasNext();) {
				Serializable object = iterator.next();
				if (!(object instanceof PublicKey))
					continue;

				PublicKey publicKey = (PublicKey) object;

				iterator.remove();

				try {
					// derive fingerprint from public key
					Fingerprint subject = new Fingerprint(publicKey);

					TrustInfo info = this.trustManager.getTrustInfo(subject);
					if (!info.equals(TrustInfo.UNKNOWN)) {
						Log.w(TAG, "(SY) Subject is already known, skipping...");
						continue;
					}

					// check for self signature & verify it
					Signature signature = selfSignatures.get(subject);

					if (!signature.verify(publicKey, publicKey))
						throw new SecurityException("Invalid signature! " + subject);

					// check if it is a new subject
					if (this.trustManager.addSubject(publicKey, signature)) {
						cPublicKeys++;
						cSignatures++;
					}
				} catch (Exception e) {
					Log.e(TAG, "(SY) - Error extracting subject!", e);
				}
			}

			//Log.d(TAG, "(SY) - Extracting all remaining signatures...");
			for (iterator = relatedData.iterator(); iterator.hasNext();) {
				Serializable object = iterator.next();
				if (!(object instanceof Signature))
					continue;

				Signature signature = (Signature) object;

				iterator.remove();

				try {
					PublicKey subject = this.trustManager.getPublicKey(signature.getSubject());
					if (subject == null)
						throw new IllegalArgumentException("Could not find subject!");

					// verify signature if issuer is known
					PublicKey issuer = this.trustManager.getPublicKey(signature.getIssuer());
					if (issuer != null && !signature.verify(issuer, subject))
						throw new SecurityException("Invalid signature!");

					// signature valid || issuer = null
					if (this.trustManager.addSignature(signature)) {
						cSignatures++;
					}
				} catch (Exception e) {
					Log.e(TAG, "(SY) - Unable to extract signature! " + signature, e);
				}
			}

			//Log.d(TAG, "(SY) - Adding new sub keys to repository");
			for (iterator = relatedData.iterator(); iterator.hasNext();) {
				Serializable object = iterator.next();
				if (!(object instanceof SubKeyEntry))
					continue;

				SubKeyEntry subKey = (SubKeyEntry) object;

				iterator.remove();

				try {
					if (this.trustManager.addSubKey(subKey.publicKey, subKey.signature))
						cSubKeys++;
				} catch (Exception e) {
					Log.e(TAG, "(SY) - Error extracting sub key! " + subKey, e);
				}
			}

			// if (cSignatures > 0) {
			//Log.d(TAG, "(SY) - Verify all newly added subjects & signatures");
			this.trustManager.refreshValidity();
			// }

			this.trustManager.updateLastSynchronization(fingerprint);
		}

		if (relatedData.size() > 0) {
			Log.w(TAG, "(SY) - Not all related data entries could be processed! " + relatedData.size());
		}
		
		///////////////////////////////
		//Log.d(TAG, "(SY) - Summary: " + cPublicKeys + ", " + cSignatures + ", " + cSubKeys);
	}

	// -- HANDSHAKE PROTOCOL

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public synchronized boolean isHandshakeRunning(Fingerprint fingerprint) {
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
				info = this.trustManager.getTrustInfo(fingerprint);
			}
			if (TrustLevel.TRUSTED.compareTo(info.level) <= 0) {
				Log.d(TAG, "(HS) Subject is already trusted!");
				this.handshakeCache.remove(fingerprint);
				this.broadcastProtocolFinish(BroadcastType.HANDSHAKE, fingerprint, true);
				return;
			}

			// request certificate, send my certificate
			HandshakeInitializeMessage send = new HandshakeInitializeMessage(this.keyManager.getPublicKey(),
					this.keyManager.getSignature(), getHostByFingerprint(fingerprint));
			//////////////////////////
			send.setSizeSerializable(getHostByFingerprint(fingerprint));
			//Log.d(TAG, "(HS) Performing handshake w/ device:  " + send.getFrom());
			//////////////////////////
			this.send(fingerprint, send);
		} catch (Exception e) {
			this.handshakeCache.remove(fingerprint);
			this.broadcastProtocolError(BroadcastType.HANDSHAKE, fingerprint, e);
		}
	}

	private void onHandshakeInitializeMessageReceived(final Fingerprint fingerprint,
			final HandshakeInitializeMessage message) {
		Log.d(TAG, "(HS) Received HandshakeInitializeMessage from " + fingerprint);
		/////////////////////////////////////////////////////////
		//Log.d(TAG, "(HS) Received HandshakeInitializeMessage from device: " + message.getFrom());
		//////////////////////////////////////////////////////
		
		try {
			// check if for that same fingerprint, already a handshake is going
			// on (if it was initiated by the other party)
			if (!message.isResponse() && this.isHandshakeRunning(fingerprint))
				throw new IllegalArgumentException("Already performing handshake with the same fingerprint");

			// verify certificate
			//Log.d(TAG, "(HS) - Verifying received self-signature");
			if (!message.getSignature().verify(message.getPublicKey(), message.getPublicKey()))
				throw new SignatureException("Received and invalid self-signature!");

			// check if this handshake was initialized by me (if not send
			// response)
			if (!message.isResponse()) {
				// check if already trusted
				TrustInfo info;
				synchronized (MUTEX_TRUST_MANAGER) {
					info = this.trustManager.getTrustInfo(fingerprint);
				}
				if (TrustLevel.TRUSTED.compareTo(info.level) <= 0) {
					//Log.d(TAG, "(HS) Subject is already trusted!");
					this.handshakeCache.remove(fingerprint);
					this.broadcastProtocolFinish(BroadcastType.HANDSHAKE, fingerprint, true);
					return;
				}
				
//				if(this.)
				
				//Log.d(TAG, "(HS) - Sending response...");
				HandshakeInitializeMessage send = new HandshakeInitializeMessage(this.keyManager.getPublicKey(),
						this.keyManager.getSignature(), getHostByFingerprint(fingerprint));
				send.setResponse(true);
				//////////////////////////								
				send.setSizeSerializable(getHostByFingerprint(fingerprint));
				Log.d(TAG, "(HS) - Sending response to device: " + getHostByFingerprint(fingerprint));
				//////////////////////////
				this.send(fingerprint, send);
			}

			// TODO: if not initialized by me, this needs to pop up somehow
			// (notification!)
			//Log.d(TAG, "(HS) - Verifying public key over a secure channel...");
			HandshakeCacheItem cache = this.handshakeCache.get(fingerprint);
			cache.message = message;
			// TODO: provide alias to keyverification
			// KeyVerifierActivity.performKeyVerification(this,
			// this.keyManager.getPublicKey(), message);
			// performKeyVerification(homePubKey, remotePubKey, remoteSignature,
			// RequestCode)
			this.onKeyVerificationFinished(fingerprint.toString(), "", true);
		} catch (Exception e) {
			this.handshakeCache.remove(fingerprint);
			this.broadcastProtocolError(BroadcastType.HANDSHAKE, fingerprint, e);
		}
	}

	private void onKeyVerificationError(String responseCode, Throwable error) {
		Log.e(TAG, "(HS) onKeyVerificationError - " + responseCode, error);

		Fingerprint partner = Fingerprint.fromData(responseCode);

		this.handshakeCache.remove(partner);

		this.broadcastProtocolError(BroadcastType.HANDSHAKE, partner, error);
	}
	
	public void removeHandshakeCache(Fingerprint fingerprint){		
		this.handshakeCache.remove(fingerprint);
	}

	private void onKeyVerificationFinished(String responseCode, String alias, boolean result) {
		//Log.d(TAG, "(HS) onKeyVerificationFinished - " + responseCode + ", " + alias + ", " + result);

		Fingerprint partner = Fingerprint.fromData(responseCode);

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
			cache.signature = this.keyManager.createSignature(cache.message.getPublicKey(), alias);

			// send my new signature
			//Log.d(TAG, "(HS) - Sending HandshakeSignatureMessage response");
			MessageAuthentication send = new HandshakeSignatureMessage(cache.signature, getHostByFingerprint(partner));
			//////////////////////////
			send.setSizeSerializable(getHostByFingerprint(partner));
			//Log.d(TAG, "(HS) - Sending HandshakeSignatureMessage response from device: " + send.getFrom());
			//////////////////////////
			
			this.send(partner, send);

			this.checkHandshakeComplete(partner);
		} catch (Exception e) {
			this.handshakeCache.remove(partner);
			this.broadcastProtocolError(BroadcastType.HANDSHAKE, partner, e);
		}
	}

	private void onHandshakeSignatureMessageReceived(final Fingerprint fingerprint,
			final HandshakeSignatureMessage message) {
		//Log.d(TAG, "(HS) Received HandshakeSignatureMessage from " + fingerprint);
		////////////////////////////////////////////////////////
		//Log.d(TAG, "(HS) Received HandshakeSignatureMessage from device: " + message.getFrom());
		////////////////////////////////////////////////////////
		
		try {
			// check cache
			if (!this.handshakeCache.containsKey(fingerprint))
				throw new IllegalStateException("HandshakeInitializeMessage was not cached! Too long ago?");

			HandshakeCacheItem cache = this.handshakeCache.get(fingerprint);
			if(cache == null)
				DeviceLog.d(null, TAG, "Error cache empty");

			Log.d(TAG, "(HS) - Verifying received signature");
			Signature signature = message.getSignature();
			
			if (!signature.verify(cache.message.getPublicKey(), this.keyManager.getPublicKey()))
				throw new SignatureException("Received signature is invalid!");

			cache.signatureRemote = signature;

			this.checkHandshakeComplete(fingerprint);
		} catch (Exception e) {
			// this.trustManager.checkValidity(fingerprint);
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
			if (!this.trustManager.addSubject(cache.message.getPublicKey(), cache.message.getSignature())) {
				TrustInfo info = this.trustManager.getTrustInfo(fingerprint);
				if (info.level == TrustLevel.TRUSTED) {
					Log.w(TAG, "(HS) Somehow this subject managed to become trusted!?!");
				} else if (info.level == TrustLevel.UNKNOWN) {
					throw new IllegalStateException(
							"Unable to add subject to repository! However, still is UNKNOWN (Inconsistency?) "
									+ fingerprint);
				}
			}

			// my signature
			//Log.d(TAG, "(HS) - Add my signature to TrustManager");
			this.trustManager.addSignature(cache.signature);

			// remote signature
			//Log.d(TAG, "(HS) - Add remote signature to TrustManager");
			this.trustManager.addSignature(cache.signatureRemote);

			//Log.d(TAG, "(HS) - Check validity of new subject");
			if (!this.trustManager.checkValidity(fingerprint))
				throw new IllegalStateException("Could not validate the trust from the new subject!");
		}

		this.handshakeCache.remove(fingerprint);
		this.broadcastProtocolFinish(BroadcastType.HANDSHAKE, fingerprint, true);

		//Log.d(TAG, "(HS) - Triggering update mechanism");
		this.onPerformSynchronization(fingerprint);
	}

	// -- BROADCAST

	public enum BroadcastType {
		HANDSHAKE, SYNCHRONIZATION;
	}

	private void broadcastProtocolFinish(BroadcastType type, Fingerprint fingerprint, boolean result) {
		//Log.d(TAG, "BROADCAST: " + type.name() + "-FINISH w/ " + fingerprint + ", result = " + result);
	}

	private void broadcastProtocolError(BroadcastType type, Fingerprint fingerprint, Throwable error) {
		Log.e(TAG, "BROADCAST: " + type.name() + "-ERROR w/ " + fingerprint, error);
	}

	// -- NETWORK

	protected final void onMessageReceived(final Fingerprint fingerprint, final MessageAuthentication message) {
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

	// best implement on another thread
	protected abstract void send(final Fingerprint fingerprint, final MessageAuthentication message) throws NetworkException;

	public DTNHost getHostByFingerprint(Fingerprint fingerprint){
		List<DTNHost> devices = new ArrayList<DTNHost>();
		devices = SimScenario.getInstance().getHosts();
		for(DTNHost host : devices){
			if(host.getFingerprint().equals(fingerprint))
				return host;
		}
		return null;
	}
	
}
