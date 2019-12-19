package auth_encryption.simulator;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import auth_encryption.core.KeyManager;
import auth_encryption.core.MessageAuthentication;
import auth_encryption.core.NetworkException;
import auth_encryption.core.TrustManager;
import auth_encryption.core.TrustProtocol;
import auth_encryption.primitives.Fingerprint;
import core.DTNHost;

/**
 * Simulated protocol instance for each device.
 */
public class SimulationProtocol extends TrustProtocol implements SimulationNetworkInterface.Receiver {
	private static final String TAG = SimulationProtocol.class.getSimpleName();

	/*
	 * Fields
	 */

	// Pseudo simulation variable (In actual implementation it is clear from
	// which device the message originates)
	private DTNHost self = null;
	
	private SimulationNetworkInterface network;
	private Set<DTNHost> lastNeighbors = null; // last known neighbors

	/**
	 * 
	 * @param self
	 *            Pseudo simulation argument (In actual implementation it is
	 *            clear from which device the message originates)
	 */
	public SimulationProtocol(String basePath, DTNHost self, KeyManager keyManager) throws Exception {
		super(keyManager, basePath);

		this.self = self;

		// initialize network interface
		this.network = new SimulationNetworkInterface(self);
	}

	public KeyManager getKeyManager() {
		return this.keyManager;
	}

	public TrustManager getTrustManager() {
		return this.trustManager;
	}
	
	public SimulationNetworkInterface getNetworkInterface() {
		return this.network;
	}

	public void performHandshake(DTNHost device) throws NetworkException {
		if (!this.lastNeighbors.contains(device))
			throw new NetworkException("Device is not available!");
			this.onPerformHandshake(device.getFingerprint());
	}

	@Override
	public /* synchronized */ void onMessageReceived(DTNHost device, MessageAuthentication message) {
		/////////////////////////////////////////////////////
		//DeviceLog.d(this.self, TAG,
			//	String.format("<RX> message (%d) from %s: %s", message.getType(), device, device.getFingerprint()));
		String subType = (String)message.getProperty("subtype");
		if(subType != null)
			DeviceLog.d(this.self, TAG,
					String.format("<RX> message (%s) from %s subtype %s", message, device, subType));
		/////////////////////////////////////////////////////
		
		/////////////////////////////////////////////////////
		//DeviceLog.d(this.self, TAG,
			//	String.format("<RX> message (%s) from %s", message, device));
		///////////////////////////////////////////////////// 
		// forward event to TrustProtocol
		this.onMessageReceived(device.getFingerprint(), message);
	}

	@Override
	public void onNeighborsChanged(Set<DTNHost> neighbors) {
		//DeviceLog.d(this.self, TAG, "onDeviceListChanged: " + neighbors.size());
		this.lastNeighbors = neighbors;

		// do not notify TrustProtocol here, yet (later in notifyNeighbors!), as
		// this leads to inconsistencies.
	}

	/**
	 * Forwards the current neighbors as a list of fingerprints to the
	 * TrustProtocol.
	 */
	public void notifyNeighbors() {
		if (this.lastNeighbors == null)
			return;

		// get list of all known fingerprints for the current neighbors
		List<Fingerprint> fpNeighbors = new ArrayList<Fingerprint>();
		for (DTNHost device : this.lastNeighbors) {
			fpNeighbors.add(device.getFingerprint());
		}

		this.onPeerListChanged(fpNeighbors);
	}

	@Override
	public void send(Fingerprint fingerprint, MessageAuthentication message) throws NetworkException {
		int ok;
		if (message == null)
			throw new NetworkException("Message cannot be null!");

		// search for neighboring device with given fingerprint
		DTNHost target = null;
	
		for (DTNHost device : this.lastNeighbors) {
			Fingerprint current = device.getFingerprint();
			
			if (!current.equals(fingerprint))
				continue;

			if (target != null)
				 ok =100 ;//DeviceLog.w(this.self, TAG, "Multiple devices w/ same fingerprint found!");

			target = device;
		}		

		if (target == null)
		{
			this.removeHandshakeCache(fingerprint);
			throw new NetworkException("This fingerprint is not available right now!");
		}

		this.network.send(target, message);
	}
}
