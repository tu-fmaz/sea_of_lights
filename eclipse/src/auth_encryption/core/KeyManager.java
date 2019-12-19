package auth_encryption.core;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicInteger;

import auth_encryption.log.Log;
import auth_encryption.primitives.AppDetails;
import auth_encryption.primitives.Config;
import auth_encryption.primitives.Fingerprint;
import auth_encryption.primitives.Signature;
import auth_encryption.primitives.SignatureParameter;
import auth_encryption.primitives.SubKeySignature;
import applications.AuthenticationApplication;

public abstract class KeyManager {
	private String TAG = KeyManager.class.getSimpleName();

	public interface InitializeCallback {
		void onInitializationSuccess();

		void onInitializationFailed(Exception e);
	}

	protected final InitializeCallback callback;

	private final String basePath;

	protected PublicKey publicKey = null;
	protected PrivateKey privateKey = null;
	private Signature signature = null;

	protected KeyManager(final String basePath, final InitializeCallback callback) {
		Log.d(TAG, "Initializing KeyManager");
		
		this.TAG += "/" + basePath.substring(basePath.length() - 4, basePath.length());

		this.callback = callback;
		this.basePath = basePath;

		// public key & private key should be loaded by subclasses!
	}

	protected final void initializationComplete() {
		Log.d(TAG, "Finishing initialization of KeyManager...");
		
		//Key will be saved on a file storage
		/*
		 * Here is necessary a path for the file, but maybe with a database 
		 * only the fields are important
		 * */
		final TrustFileManager fileManager = TrustFileManager.getInstance(this.basePath);

		try {
			//This section checks if we have already created our owner public key
			if (fileManager.hasSignature(this.publicKey, this.publicKey)) {
				Log.d(TAG, "- Signature already exists: Loading");
				// check if signature (& public key) have already been stored
				this.signature = fileManager.loadSignature(this.publicKey, this.publicKey);

				this.completeSuccess();

				return;
			}

			Log.d(TAG, "- First time, creating self-signature");

			// create new signature and store everything
			this.signature = this.createSignature(this.publicKey, null); // TODO: add my own name
			fileManager.savePublicKey(this.publicKey, this.signature);

			this.completeSuccess();
		} catch (Exception e) {
			this.initializationError(e);
		}
	}

	private final void completeSuccess() {
		if (KeyManager.this.callback == null)
			return;

		new Thread(new Runnable() {
			@Override
			public void run() {
				KeyManager.this.callback.onInitializationSuccess();
			}
		}).start();
	}

	protected final void initializationError(final Exception error) {
		if (KeyManager.this.callback == null)
			return;

		new Thread(new Runnable() {
			@Override
			public void run() {
				KeyManager.this.callback.onInitializationFailed(error);
			}
		}).start();
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

	public AtomicInteger count = new AtomicInteger(0); // delete

	private byte[] sign(byte[] data) throws Exception {
		if (this.privateKey == null)
			throw new IllegalStateException("Key Manager was not initialized properly!");

		count.incrementAndGet();

		SignatureParameter signParams = AuthenticationApplication.KEY_PARAMETER;
		
		java.security.Signature sig = java.security.Signature.getInstance(signParams.getSignatureAlgorithm());
		sig.initSign(this.privateKey);
		sig.update(data);
		return sig.sign();
	}

	/**
	 * Creates a new signature.
	 *
	 * @param subject
	 */
	public Signature createSignature(PublicKey subject, String alias) throws Exception {
		Signature result = new Signature(this.publicKey, subject);
		result.setAlias(alias);
		result.setData(this.sign(result.getDigestData(subject)));
		return result;
	}

	public SubKeySignature createSubKeySignature(byte[] subKey, AppDetails appDetails, boolean bindToApp, String tag) throws Exception {
		SubKeySignature result = new SubKeySignature(this.publicKey, subKey, appDetails);

		result.setBindToApp(bindToApp);
		result.setTag(tag);
		result.setData(this.sign(result.getDigestData(subKey)));

		return result;
	}
}
