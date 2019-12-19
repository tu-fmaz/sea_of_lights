package auth_encryption.simulator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import applications.AuthenticationApplication;
import auth_encryption.core.KeyManager;
import auth_encryption.primitives.Config;

/**
 * Simple software-based key manager w/o a password for simulation purposes.
 */
public class SimulationKeyManager extends KeyManager {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private final String basePath;

	public SimulationKeyManager(final String basePath, final KeyManager.InitializeCallback callback) throws Exception {
		super(basePath, callback);

		this.basePath = basePath;

		if (this.readData()) {
			this.initializationComplete();
			return;
		}

		KeyPairGenerator kg = KeyPairGenerator.getInstance(AuthenticationApplication.KEY_PARAMETER.getAlgorithm());
		kg.initialize(AuthenticationApplication.KEY_PARAMETER.getKeySize());
		KeyPair kp = kg.generateKeyPair();
		this.publicKey = kp.getPublic();
		this.privateKey = kp.getPrivate();
		this.saveData();
		this.initializationComplete();
	}

	private boolean readData() {
		File file = new File(this.basePath + "/keystore.kpair");
		if (!file.exists() || !file.isFile())
			return false;

		try {
			FileInputStream fis = new FileInputStream(file);
			ObjectInputStream ois = new ObjectInputStream(fis);
			KeyPair result = (KeyPair) ois.readObject();
			ois.close();
			fis.close();

			this.publicKey = result.getPublic();
			this.privateKey = result.getPrivate();
		} catch (Exception e) {
			return false;
		}

		return true;
	}

	private void saveData() throws Exception {
		File file = new File(this.basePath + "/keystore.kpair");

		if (!file.getParentFile().exists())
			file.getParentFile().mkdirs();

		KeyPair result = new KeyPair(this.publicKey, this.privateKey);

		FileOutputStream fos = new FileOutputStream(file);
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(result);
		oos.close();
		fos.close();
	}
}
