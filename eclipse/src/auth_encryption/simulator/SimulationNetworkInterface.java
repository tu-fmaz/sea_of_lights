package auth_encryption.simulator;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;

import auth_encryption.core.HandshakeInitializeMessage;
import auth_encryption.core.HandshakeSignatureMessage;
import auth_encryption.core.MessageAuthentication;
import auth_encryption.core.SyncMessage;
import auth_encryption.core.SyncRequestMessage;
import core.DTNHost;

/**
 * Network Interface for the simulation (simply forwards messages to the destined devices).
 */
public class SimulationNetworkInterface {
	private static final String TAG = SimulationNetworkInterface.class.getSimpleName();

	/**
	 * Callback for network activities.
	 */
	public interface Receiver {
		void onMessageReceived(DTNHost device, MessageAuthentication message);

		void onNeighborsChanged(Set<DTNHost> neighbors);

		void notifyNeighbors();
	}

	/*
	 * Fields
	 */
	private DTNHost self = null;
	public Map<Integer, AtomicLong> counts = new HashMap<Integer, AtomicLong>();
	/////////////////////////////////////
	public Map<Integer, AtomicLong> countsMessage = new HashMap<Integer, AtomicLong>();
	/////////////////////////////////////

	/**
	 * Constructor.
	 * 
	 * @param self
	 */
	public SimulationNetworkInterface(DTNHost self) {
		this.self = self;

		this.counts.put(MessageAuthentication.TYPE_ALL, new AtomicLong(0));
		this.counts.put(SyncRequestMessage.TYPE_SYNC_REQUEST, new AtomicLong(0));
		this.counts.put(SyncMessage.TYPE_SYNC, new AtomicLong(0));
	}

	/**
	 * Broadcasts a specific message to all given devices.
	 * 
	 * @param targets
	 *            Pseudo simulation argument (In actual implementation broadcast
	 *            signal does not need to specify targets)
	 * @param message
	 *            Message to be broadcasted
	 */

	public void broadcast(List<DTNHost> targets, MessageAuthentication message) {
		if (message == null)
			return;

		if (targets == null || targets.size() == 0)
			return;
		
		////////////////////////////////////////////////
		//DeviceLog.d(this.self, TAG,
			//	String.format("<BX> message (%d) to %d devices", message.getType(), targets.size()));
		String subType = (String)message.getProperty("subtype");
		if(subType!=null)
			DeviceLog.d(this.self, TAG,
				String.format("<BX> message (%s) to %d devices",subType, targets.size()));
		
		////////////////////////////////////////////////
				
		for (DTNHost device : targets) {
			// forward to normal send method
			this.send(device, message);
		}
	}

	/**
	 * Sends a specific message to the given target.
	 * 
	 * @param target
	 *            Device message is intended to
	 * @param message
	 *            Message to be send
	 */
	public void send(final DTNHost target, final MessageAuthentication message) {
		if (target == null || message == null)
			return;
		
		////////////////////////////////////////////////
		//DeviceLog.d(this.self, TAG, String.format("<TX> message (%d) to %s", message.getType(), target));
		String subType = (String)message.getProperty("subtype");
		if(subType!=null)
			DeviceLog.d(this.self, TAG, String.format("<TX> message subtype %s to %s", subType, target));
		////////////////////////////////////////////////
		
		// register network task (run on the thread pool)
		Future<?> future = SimulationConfig.SIMULATION_THREADS.submit(new Runnable() {
			@Override
			public void run() {
				////////////////////////////////////////////////
				//DeviceLog.d(self, TAG, "-> " + target.getUUID());
				//DeviceLog.d(self, TAG, "-> " + target);
				////////////////////////////////////////////////
				try {
					// add artificial network delay.
					Thread.sleep(SimulationConfig.NETWORK_SEND_DELAY);
				} catch (Exception e) {
					// swallow
				}
				if (target.getReceiver() != null){					
					target.getReceiver().onMessageReceived(SimulationNetworkInterface.this.self, message);				
				}
				// apply metrics
				SimulationNetworkInterface.this.measureData(message);
			}
		});

		// add to message queue (in order for every message to be executed in order)
		SimulationConfig.SIMULATION_FUTURE_QUEUE.add(future);
	}

	/**
	 * Measures the actual data that is being sent(!), reception is not measured as this is redundant.
	 * @param message
	 */
	public void measureData(final MessageAuthentication message) {
		// only measure for synchronization messages
		if (message.getType() != SyncMessage.TYPE_SYNC && message.getType() != SyncRequestMessage.TYPE_SYNC_REQUEST)
			return;

		// register count for given message type
		long size = SimulationUtils.getNetworkObjectSize(message);
		this.counts.get(message.getType()).addAndGet(size);
		this.counts.get(MessageAuthentication.TYPE_ALL).addAndGet(size);
	}
}
