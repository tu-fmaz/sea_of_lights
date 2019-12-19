/*
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core;

import java.io.File;
import java.io.FileFilter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import applications.AuthenticationApplication;
import auth_encryption.core.HandshakeInitializeMessage;
import auth_encryption.core.HandshakeSignatureMessage;
import auth_encryption.core.KeyManager;
import auth_encryption.core.MessageAuthentication;
import auth_encryption.core.NetworkException;
import auth_encryption.core.SyncMessage;
import auth_encryption.core.SyncRequestMessage;
import auth_encryption.core.TrustManager;
import auth_encryption.primitives.AppDetails;
import auth_encryption.primitives.Fingerprint;
import auth_encryption.primitives.Signature;
import auth_encryption.primitives.SubKeySignature;
import auth_encryption.simulator.DeviceLog;
import auth_encryption.simulator.Metrics;
import auth_encryption.simulator.Metrics.BandwidthType;
import auth_encryption.simulator.Metrics.MemoryType;
import auth_encryption.simulator.Metrics.MessageType;
import auth_encryption.simulator.Metrics.PerformanceType;
import auth_encryption.simulator.SimulationConfig;
import auth_encryption.simulator.SimulationKeyManager;
import auth_encryption.simulator.SimulationNetworkInterface;
import auth_encryption.simulator.SimulationProtocol;
import auth_encryption.simulator.SimulationUtils;
import movement.MovementModel;
import movement.Path;
import routing.MessageRouter;
import routing.util.RoutingInfo;

import static core.Constants.DEBUG;

/**
 * A DTN capable host.
 */
public class DTNHost implements Comparable<DTNHost> {
	private static int nextAddress = 0;
	private int address;

	private Coord location; 	// where is the host
	private Coord destination;	// where is it going

	private MessageRouter router;
	private MovementModel movement;
	private Path path;
	private double speed;
	private double nextTimeToMove;
	private String name;
	private List<MessageListener> msgListeners;
	private List<MovementListener> movListeners;
	private List<NetworkInterface> net;
	private List<Connection> allConnections;
	private ModuleCommunicationBus comBus;

	/**
	 * START OF THE AUTHENTICATION STAFF
	 * info for the authentication protocol bzw. trust manager
	 * */
	private SimulationProtocol protocol = null;
	private final Random random;
	private static final String TAG = DTNHost.class.getSimpleName();
	private final String uuid;
	public int STEPHOST = 0;
	private double timeBefore = 0;
	
	private Map<DTNHost, Boolean> participatingInSync = new HashMap<>();
	private Map<DTNHost, Boolean> participatingInHandshake = new HashMap<>();
	
	/**
	 * END OF THE AUTHENTICATION STAFF
	 * */
	
	static {
		DTNSim.registerForReset(DTNHost.class.getCanonicalName());
		reset();
	}
	/**
	 * Creates a new DTNHost.
	 * @param msgLs Message listeners
	 * @param movLs Movement listeners
	 * @param groupId GroupID of this host
	 * @param interf List of NetworkInterfaces for the class
	 * @param comBus Module communication bus object
	 * @param mmProto Prototype of the movement model of this host
	 * @param mRouterProto Prototype of the message router of this host
	 */
	public DTNHost(List<MessageListener> msgLs,
			List<MovementListener> movLs,
			String groupId, List<NetworkInterface> interf,
			ModuleCommunicationBus comBus,
			MovementModel mmProto, MessageRouter mRouterProto, 
			String uuid) {
		this.comBus = comBus;
		this.location = new Coord(0,0);
		this.address = getNextAddress();
		this.name = groupId+address;
		this.net = new ArrayList<NetworkInterface>();
		this.allConnections = new ArrayList<Connection>();

		/**
		 * START AUTHENTICATION
		 * */
		this.random = SimulationConfig.RANDOM;
		this.uuid = uuid;

		/**
		 * END AUTHENTICATION
		 * */
		
		for (NetworkInterface i : interf) {
			NetworkInterface ni = i.replicate();
			ni.setHost(this);
			net.add(ni);
		}

		// TODO - think about the names of the interfaces and the nodes
		//this.name = groupId + ((NetworkInterface)net.get(1)).getAddress();

		this.msgListeners = msgLs;
		this.movListeners = movLs;

		// create instances by replicating the prototypes
		this.movement = mmProto.replicate();
		this.movement.setComBus(comBus);
		this.movement.setHost(this);
		setRouter(mRouterProto.replicate());
		
		
		

		this.location = movement.getInitialLocation();

		this.nextTimeToMove = movement.nextPathAvailable();
		this.path = null;

		if (movLs != null) { // inform movement listeners about the location
			for (MovementListener l : movLs) {
				l.initialLocation(this, this.location);
			}
		}
		
		
		
		//START AUTHENTICATION
		DeviceLog.d(this, TAG, "Successfully created!");
		//END AUTHENTICATION
	}

	/////////////////////////////////////////////////////
	/**
	* Pseudo simulation method. (Needs to be separate since "this" cannot be
	* passed in constructor)
	*/
	public void initializeProtocol() throws Exception {
		DeviceLog.d(this, TAG, "Initializing protocol...");

		// initialize protocol

		String basePath = SimulationConfig.SIMULATION_PATH + this.uuid;
		this.protocol = new SimulationProtocol(basePath, this,
				new SimulationKeyManager(basePath, new KeyManager.InitializeCallback() {
					@Override
					public void onInitializationSuccess() {
						DeviceLog.d(DTNHost.this, TAG, "- Initialization successful!");
					}

					@Override
					public void onInitializationFailed(Exception e) {
						DeviceLog.e(DTNHost.this, TAG, "- Initialization failed!", e);
					}
				}));

		// initialize metrics
		Metrics.recordInitialization(DTNHost.this);
		
		this.timeBefore = SimClock.getTime();
	}

	public void performHandshake(DTNHost device) throws NetworkException {
		//DeviceLog.d(this, TAG, "Handshake w/ " + device.toString());
		DeviceLog.d(this, TAG, "Handshake w/ " + device);

		this.protocol.performHandshake(device);
	}

	public String getUUID(){
		return this.uuid;
	}

	public SimulationNetworkInterface.Receiver getReceiver(){
		return this.protocol;
	}
	
	public SimulationNetworkInterface getSimulationNetworkInterface(){
		return this.protocol.getNetworkInterface();
	}

	/**
	* Functions for the authentication and trust protocol
	* */
	public Fingerprint getFingerprint() {
		return this.protocol.getKeyManager().getFingerprint();
	}

	/**
	* Generate required sub-keys for this device.
	*/
	public void generateSubKeys() {
		try {
			int numKeys = this.random.nextInt(SimulationConfig.TRUST_SUBKEYS_MAX - SimulationConfig.TRUST_SUBKEYS_MIN + 1) + SimulationConfig.TRUST_SUBKEYS_MIN;

			for (int i = 0; i < numKeys; i++) {
				byte[] subKey = new byte[SimulationConfig.TRUST_SIZE_SUBKEY];
				this.random.nextBytes(subKey);

				AppDetails creatingApp = new AppDetails("net.kolhagen.thesis.apps.test");

				SubKeySignature signature = this.protocol.getKeyManager().createSubKeySignature(subKey, creatingApp, false, this.getUUID());

				this.protocol.getTrustManager().addSubKey(subKey, signature);
			}
		} catch (Exception e) {
			DeviceLog.e(this, TAG, "Unable to generate sub keys!", e);
		}
	}

	public void recordMetrics() {
		final TrustManager tm = this.protocol.getTrustManager();
		final String deviceDir = SimulationConfig.SIMULATION_PATH + this.uuid;

		// -- Record Trust Propagation
		long direct = tm.measureNumDirectTrustRelations();
		long indirect = tm.measureNumIndirectTrustRelations();
		Metrics.recordDirectPropagation(this, direct);
		Metrics.recordIndirectPropagation(this, indirect);
		Metrics.recordTotalPropagation(this, direct + indirect);

		// -- Record Performance
		float num = (0.0f + Signature.COUNT.getAndSet(0) + SubKeySignature.COUNT.getAndSet(0))
				/ SimulationConfig.NETWORK_NUM_DEVICES;

		Metrics.recordPerformance(this, PerformanceType.NUM_VERIFICATIONS, num);
		Metrics.recordPerformance(this, PerformanceType.NUM_SIGNATURES,
				this.protocol.getKeyManager().count.getAndSet(0));
		int steps = this.STEPHOST ;/// 10;
		if ((steps == 1) || (steps % SimulationConfig.METRICS_INITIALIZATION_INTERVAL) == 0) {
			try {
				long start = System.currentTimeMillis();
				TrustManager manager = new TrustManager(deviceDir, this.protocol.getKeyManager().getPublicKey());
				manager.initialize();
				long duration = System.currentTimeMillis() - start;
				if (!manager.equals(this.protocol.getTrustManager())) {
					// print additional logs if the re-initialization differs from the in-memory repository
					DeviceLog.e(this, TAG, "!!! CRITICAL ERROR: re-deduction failed (TM out of sync) !!!");
					DeviceLog.e(this, TAG, this.protocol.getTrustManager().debugCompare(manager));
					this.protocol.getTrustManager().refreshValidity();
					DeviceLog.e(this, TAG, this.protocol.getTrustManager().debugCompare(manager));

					// abort simulation
					System.exit(0);
				}

				Metrics.recordPerformance(this, PerformanceType.TIME_INITIALIZATION, duration);
			} catch (Exception e) {
				DeviceLog.e(this, TAG, "Error: Could not measure initialization time!", e);
			}

			// reset verification counts
			Signature.COUNT.set(0);
			SubKeySignature.COUNT.set(0);
		}

		// -- Record Bandwidth

		final SimulationNetworkInterface nwi = this.protocol.getNetworkInterface();

		Metrics.recordSynchronizationBandwidth(this, BandwidthType.TOTAL,
		nwi.counts.get(MessageAuthentication.TYPE_ALL).getAndSet(0));
		Metrics.recordSynchronizationBandwidth(this, BandwidthType.SYNC_QUERY,
		nwi.counts.get(SyncRequestMessage.TYPE_SYNC_REQUEST).getAndSet(0));
		Metrics.recordSynchronizationBandwidth(this, BandwidthType.SYNC_RESPONSE,
		nwi.counts.get(SyncMessage.TYPE_SYNC).getAndSet(0));

		// -- Record Message generates
		//Metrics.recordMessage(this, MessageType.SYNC, nwi.countsMessage.get(SyncMessage.TYPE_SYNC).getAndSet(0));
		//Metrics.recordMessage(this, MessageType.SYNC_REQUEST, nwi.countsMessage.get(SyncRequestMessage.TYPE_SYNC_REQUEST).getAndSet(0));
		//Metrics.recordMessage(this, MessageType.HS_INIT, nwi.countsMessage.get(HandshakeInitializeMessage.TYPE_HANDSHAKE_INIT).getAndSet(0));
		//Metrics.recordMessage(this, MessageType.HS_SIG, nwi.countsMessage.get(HandshakeSignatureMessage.TYPE_HANDSHAKE_SIGNATURE).getAndSet(0));		
		
		// -- Record Memory
		final File trustDir = new File(deviceDir, "trust/");
		
		Metrics.recordSizeTrustDirectory(this, MemoryType.TOTAL, SimulationUtils.directorySize(trustDir, null));
		Metrics.recordSizeTrustDirectory(this, MemoryType.PUBLIC_KEYS,
				SimulationUtils.directorySize(trustDir, new FileFilter() {
					@Override
					public boolean accept(File pathname) {
						if (pathname.isDirectory())
							return true;
		
						return pathname.getAbsolutePath().endsWith("/keys/public.key");
					}
				}));
		Metrics.recordSizeTrustDirectory(this, MemoryType.SIGNATURES,
				SimulationUtils.directorySize(trustDir, new FileFilter() {
					@Override
					public boolean accept(File pathname) {
						if (pathname.isDirectory())
							return true;

						if (pathname.getParent().endsWith("/keys"))
							return false;

						return pathname.getName().endsWith(".sig");
					}
				}));
		Metrics.recordSizeTrustDirectory(this, MemoryType.SUB_KEYS,
				SimulationUtils.directorySize(trustDir, new FileFilter() {
					@Override
					public boolean accept(File pathname) {
						if (pathname.isDirectory())
							return true;

						if (!pathname.getParent().endsWith("/keys"))
							return false;

						final String name = pathname.getName();
						return name.endsWith(".key") && !name.equals("public.key");
					}
				}));
		Metrics.recordSizeTrustDirectory(this, MemoryType.SUB_KEY_SIGNATURES,
				SimulationUtils.directorySize(trustDir, new FileFilter() {
					@Override
					public boolean accept(File pathname) {
						if (pathname.isDirectory())
							return true;

						if (!pathname.getParent().endsWith("/keys"))
							return false;

						return pathname.getName().endsWith(".sig");
					}
				}));
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((uuid == null) ? 0 : uuid.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DTNHost other = (DTNHost) obj;
		if (uuid == null) {
			if (other.uuid != null)
				return false;
		} else if (!uuid.equals(other.uuid))
			return false;
		return true;
	}
	
	public void setParticipingInHS(DTNHost device, boolean value){
		this.participatingInHandshake.put(device, value);
	}
	
	public void setParticipingInSync(DTNHost device, boolean value){
		this.participatingInSync.put(device, value);
	}
	
	public boolean isParticipingInSync(DTNHost device){
		if(this.participatingInSync.containsKey(device))
			return this.participatingInSync.get(device);
		else
			this.participatingInSync.put(device, true);
		return false;
	}
	
	public boolean isParticipingInHS(DTNHost device){
		if(this.participatingInHandshake.containsKey(device))
			return this.participatingInHandshake.get(device);
		else
			this.participatingInHandshake.put(device, true);
		return false;
	}
	
	public boolean containsPartnerHS(DTNHost device){
		return this.participatingInHandshake.containsKey(device);
	}
	
	public boolean containsPartnerSync(DTNHost device){
		return this.participatingInSync.containsKey(device);
	}
/////////////////////////////////////////////////////
	
	/**
	 * Returns a new network interface address and increments the address for
	 * subsequent calls.
	 * @return The next address.
	 */
	private synchronized static int getNextAddress() {
		return nextAddress++;
	}

	/**
	 * Reset the host and its interfaces
	 */
	public static void reset() {
		nextAddress = 0;
	}

	/**
	 * Returns true if this node is actively moving (false if not)
	 * @return true if this node is actively moving (false if not)
	 */
	public boolean isMovementActive() {
		return this.movement.isActive();
	}

	/**
	 * Returns true if this node's radio is active (false if not)
	 * @return true if this node's radio is active (false if not)
	 */
	public boolean isRadioActive() {
		// Radio is active if any of the network interfaces are active.
		for (final NetworkInterface i : this.net) {
			if (i.isActive()) return true;
		}
		return false;
	}

	/**
	 * Set a router for this host
	 * @param router The router to set
	 */
	private void setRouter(MessageRouter router) {
		router.init(this, msgListeners);
		this.router = router;
	}

	/**
	 * Returns the router of this host
	 * @return the router of this host
	 */
	public MessageRouter getRouter() {
		return this.router;
	}

	/**
	 * Returns the network-layer address of this host.
	 */
	public int getAddress() {
		return this.address;
	}

	/**
	 * Returns this hosts's ModuleCommunicationBus
	 * @return this hosts's ModuleCommunicationBus
	 */
	public ModuleCommunicationBus getComBus() {
		return this.comBus;
	}

    /**
	 * Informs the router of this host about state change in a connection
	 * object.
	 * @param con  The connection object whose state changed
	 */
	public void connectionUp(Connection con) {
		this.allConnections.add(con);
		this.router.changedConnection(con);
	}

	public void connectionDown(Connection con) {
		this.allConnections.remove(con);
		this.router.changedConnection(con);
	}

	/**
	 * Returns an immutable list of connections this host has with other hosts
	 * @return an immutable list of connections this host has with other hosts
	 */
	public List<Connection> getConnections() {
		return Collections.unmodifiableList(allConnections);
	}

	/**
	 * Returns the current location of this host.
	 * @return The location
	 */
	public Coord getLocation() {
		return this.location;
	}

	/**
	 * Returns the Path this node is currently traveling or null if no
	 * path is in use at the moment.
	 * @return The path this node is traveling
	 */
	public Path getPath() {
		return this.path;
	}


	/**
	 * Sets the Node's location overriding any location set by movement model
	 * @param location The location to set
	 */
	public void setLocation(Coord location) {
		this.location = location.clone();
	}

	/**
	 * Sets the Node's name overriding the default name (groupId + netAddress)
	 * @param name The name to set
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Returns the messages in a collection.
	 * @return Messages in a collection
	 */
	public Collection<Message> getMessageCollection() {
		return this.router.getMessageCollection();
	}

	/**
	 * Returns the number of messages this node is carrying.
	 * @return How many messages the node is carrying currently.
	 */
	public int getNrofMessages() {
		return this.router.getNrofMessages();
	}

	/**
	 * Returns the buffer occupancy percentage. Occupancy is 0 for empty
	 * buffer but can be over 100 if a created message is bigger than buffer
	 * space that could be freed.
	 * @return Buffer occupancy percentage
	 */
	public double getBufferOccupancy() {
		long bSize = router.getBufferSize();
		long freeBuffer = router.getFreeBufferSize();
		return 100*((bSize-freeBuffer)/(bSize * 1.0));
	}

	/**
	 * Returns routing info of this host's router.
	 * @return The routing info.
	 */
	public RoutingInfo getRoutingInfo() {
		return this.router.getRoutingInfo();
	}

	/**
	 * Returns the interface objects of the node
	 */
	public List<NetworkInterface> getInterfaces() {
		return net;
	}

	/**
	 * Find the network interface based on the index
	 */
	public NetworkInterface getInterface(int interfaceNo) {
		NetworkInterface ni = null;
		try {
			ni = net.get(interfaceNo-1);
		} catch (IndexOutOfBoundsException ex) {
			throw new SimError("No such interface: "+interfaceNo +
					" at " + this);
		}
		return ni;
	}

	/**
	 * Find the network interface based on the interfacetype
	 */
	protected NetworkInterface getInterface(String interfacetype) {
		for (NetworkInterface ni : net) {
			if (ni.getInterfaceType().equals(interfacetype)) {
				return ni;
			}
		}
		return null;
	}

	/**
	 * Force a connection event
	 */
	public void forceConnection(DTNHost anotherHost, String interfaceId,
			boolean up) {
		NetworkInterface ni;
		NetworkInterface no;

		if (interfaceId != null) {
			ni = getInterface(interfaceId);
			no = anotherHost.getInterface(interfaceId);

			assert (ni != null) : "Tried to use a nonexisting interfacetype "+interfaceId;
			assert (no != null) : "Tried to use a nonexisting interfacetype "+interfaceId;
		} else {
			ni = getInterface(1);
			no = anotherHost.getInterface(1);

			assert (ni.getInterfaceType().equals(no.getInterfaceType())) :
				"Interface types do not match.  Please specify interface type explicitly";
		}

		if (up) {
			ni.createConnection(no);
		} else {
			ni.destroyConnection(no);
		}
	}

	/**
	 * for tests only --- do not use!!!
	 */
	public void connect(DTNHost h) {
		if (DEBUG) Debug.p("WARNING: using deprecated DTNHost.connect" +
			"(DTNHost) Use DTNHost.forceConnection(DTNHost,null,true) instead");
		forceConnection(h,null,true);
	}

	/**
	 * Updates node's network layer and router.
	 * @param simulateConnections Should network layer be updated too
	 */
	public void update(boolean simulateConnections) {
		if (!isRadioActive()) {
			// Make sure inactive nodes don't have connections
			tearDownAllConnections();
			return;
		}

		if (simulateConnections) {
			for (NetworkInterface i : net) {
				i.update();
			}
		}
		this.router.update();
	}

	/**
	 * Tears down all connections for this host.
	 */
	private void tearDownAllConnections() {
		for (NetworkInterface i : net) {
			// Get all connections for the interface
			List<Connection> conns = i.getConnections();
			if (conns.size() == 0) continue;

			// Destroy all connections
			List<NetworkInterface> removeList =
				new ArrayList<NetworkInterface>(conns.size());
			for (Connection con : conns) {
				removeList.add(con.getOtherInterface(i));
			}
			for (NetworkInterface inf : removeList) {
				i.destroyConnection(inf);
			}
		}
	}

	/**
	 * Moves the node towards the next waypoint or waits if it is
	 * not time to move yet
	 * @param timeIncrement How long time the node moves
	 */
	public void move(double timeIncrement) {
		double possibleMovement;
		double distance;
		double dx, dy;

		if (!isMovementActive() || SimClock.getTime() < this.nextTimeToMove) {
			return;
		}
		if (this.destination == null) {
			if (!setNextWaypoint()) {
				return;
			}
		}

		possibleMovement = timeIncrement * speed;
		distance = this.location.distance(this.destination);

		while (possibleMovement >= distance) {
			// node can move past its next destination
			this.location.setLocation(this.destination); // snap to destination
			possibleMovement -= distance;
			if (!setNextWaypoint()) { // get a new waypoint
				return; // no more waypoints left
			}
			distance = this.location.distance(this.destination);
		}

		// move towards the point for possibleMovement amount
		dx = (possibleMovement/distance) * (this.destination.getX() -
				this.location.getX());
		dy = (possibleMovement/distance) * (this.destination.getY() -
				this.location.getY());
		this.location.translate(dx, dy);
	}

	/**
	 * Sets the next destination and speed to correspond the next waypoint
	 * on the path.
	 * @return True if there was a next waypoint to set, false if node still
	 * should wait
	 */
	private boolean setNextWaypoint() {
		if (path == null) {
			path = movement.getPath();
		}

		if (path == null || !path.hasNext()) {
			this.nextTimeToMove = movement.nextPathAvailable();
			this.path = null;
			return false;
		}

		this.destination = path.getNextWaypoint();
		this.speed = path.getSpeed();

		if (this.movListeners != null) {
			for (MovementListener l : this.movListeners) {
				l.newDestination(this, this.destination, this.speed);
			}
		}

		return true;
	}

	/**
	 * Sends a message from this host to another host
	 * @param id Identifier of the message
	 * @param to Host the message should be sent to
	 */
	public void sendMessage(String id, DTNHost to) {
		this.router.sendMessage(id, to);
	}

	/**
	 * Start receiving a message from another host
	 * @param m The message
	 * @param from Who the message is from
	 * @return The value returned by
	 * {@link MessageRouter#receiveMessage(Message, DTNHost)}
	 */
	public int receiveMessage(Message m, DTNHost from) {
		return this.router.receiveMessage(m, from);
	}

	/**
	 * Requests for deliverable message from this host to be sent trough a
	 * connection.
	 * @param con The connection to send the messages trough
	 * @return True if this host started a transfer, false if not
	 */
	public boolean requestDeliverableMessages(Connection con) {
		return this.router.requestDeliverableMessages(con);
	}

	/**
	 * Informs the host that a message was successfully transferred.
	 * @param id Identifier of the message
	 * @param from From who the message was from
	 */
	public void messageTransferred(String id, DTNHost from) {
		this.router.messageTransferred(id, from);
	}

	/**
	 * Informs the host that a message transfer was aborted.
	 * @param id Identifier of the message
	 * @param from From who the message was from
	 * @param bytesRemaining Nrof bytes that were left before the transfer
	 * would have been ready; or -1 if the number of bytes is not known
	 */
	public void messageAborted(String id, DTNHost from, int bytesRemaining) {
		this.router.messageAborted(id, from, bytesRemaining);
	}

	/**
	 * Creates a new message to this host's router
	 * @param m The message to create
	 */
	public void createNewMessage(Message m) {
		this.router.createNewMessage(m);
	}

	/**
	 * Deletes a message from this host
	 * @param id Identifier of the message
	 * @param drop True if the message is deleted because of "dropping"
	 * (e.g. buffer is full) or false if it was deleted for some other reason
	 * (e.g. the message got delivered to final destination). This effects the
	 * way the removing is reported to the message listeners.
	 */
	public void deleteMessage(String id, boolean drop) {
		this.router.deleteMessage(id, drop);
	}

	/**
	 * Returns a string presentation of the host.
	 * @return Host's name
	 */
	public String toString() {
		return name;
	}

	/**
	 * Checks if a host is the same as this host by comparing the object
	 * reference
	 * @param otherHost The other host
	 * @return True if the hosts objects are the same object
	 */
	public boolean equals(DTNHost otherHost) {
		return this == otherHost;
	}

	/**
	 * Compares two DTNHosts by their addresses.
	 * @see Comparable#compareTo(Object)
	 */
	public int compareTo(DTNHost h) {
		return this.getAddress() - h.getAddress();
	}

	public String getTimeToString(double time){
		int precision = 2;
		String duration = String.format("%." + precision + "f", time);
		
		return duration;
	}
	
	public void setTimeBefore(double time){
		this.timeBefore = time;
	}
	
	public double getTimeBefore(){
		return this.timeBefore;
	}
	
	public boolean isNextStep(){
		double actual = Double.parseDouble(getTimeToString(SimClock.getTime()));
		double before = Double.parseDouble(getTimeToString(this.timeBefore));
		if((actual - before) > AuthenticationApplication.HS_STEPS) 
			return true;
		return false;
	}
}
