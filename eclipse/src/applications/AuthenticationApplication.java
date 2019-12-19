/*
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details.
 */

package applications;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import auth_encryption.core.HandshakeInitializeMessage;
import auth_encryption.core.HandshakeSignatureMessage;
import auth_encryption.core.MessageAuthentication;
import auth_encryption.core.SyncMessage;
import auth_encryption.core.SyncRequestMessage;
import auth_encryption.log.Log;
import auth_encryption.primitives.Config;
import auth_encryption.primitives.Fingerprint;
import auth_encryption.simulator.DeviceLog;
import auth_encryption.simulator.Metrics;
import auth_encryption.simulator.SimulationConfig;
import auth_encryption.simulator.SimulationNetworkInterface;
import report.PingAppReporter;
import core.Application;
import core.Connection;
import core.DTNHost;
import core.Message;
import core.Settings;
import core.SimClock;
import core.SimScenario;
import core.World;

import java.io.File;
import java.io.Serializable;


import java.security.PublicKey;
import java.text.SimpleDateFormat;

import auth_encryption.primitives.Signature;
import auth_encryption.primitives.SignatureParameter;

/**
 * Simple ping application to demonstrate the application support. The
 * application can be configured to send pings with a fixed interval or to only
 * answer to pings it receives. When the application receives a ping it sends
 * a pong message in response.
 *
 * The corresponding <code>PingAppReporter</code> class can be used to record
 * information about the application behavior.
 *
 * @see PingAppReporter
 * @author teemuk
 */
public class AuthenticationApplication extends Application {

	/** Application ID */
	public static final String APP_ID = "AuthenticationApplication";
	//public static volatile int STEP = 0;
	
	private static final String TAG = AuthenticationApplication.class.getSimpleName();
	/** Destination address range - inclusive lower, exclusive upper */
	public static final String AUTH_STEPS = "steps";
	public static final String TRUST = "degree";
	public static final String KEYPARM = "keyparm";
	public static final String RUNS = "runs";
	// Private vars
	////////////////////////////////////////////////
	private List<DTNHost> devices = new ArrayList<DTNHost>();
	private Map<DTNHost,Set<DTNHost>> recentNeighbors = null;
	private Random random = null;
	/** Simulation end time */
	public static int NETWORK_NUM_DEVICES;
	/** number of host groups */
	int nrofGroups;
	public static int SIMULATION_STEPS = 0;
	
	public static double HS_STEPS = 0;
	
	public static int TRUST_DEGREE;
	
	public static SignatureParameter KEY_PARAMETER;
	
	public static int NUMBEROFRUNS;
	
	public static long [] seeds = SimulationConfig.fillSeeds(5);
	////////////////////////////////////////////////
	
	/**
	 * Creates a new ping application with the given settings.
	 *
	 * @param s	Settings to use for initializing the application.
	 */
	public AuthenticationApplication(Settings s) {
		HS_STEPS = s.getDouble(AUTH_STEPS);
		TRUST_DEGREE = s.getInt(TRUST);
		NUMBEROFRUNS = s.getInt(RUNS);
		
		if(s.getBoolean(KEYPARM))
			KEY_PARAMETER = SignatureParameter.ECDSA;
		else{
			KEY_PARAMETER = SignatureParameter.RSA;
		}
		
		System.out.println("Degree : " + TRUST_DEGREE + ", RUNS: " + NUMBEROFRUNS +", KEY: " + KEY_PARAMETER);
		
		//System.out.println("Seed0: " + seeds[0] + ", Seed1: " + seeds[1] + ", Seed2: " + seeds[2]);
		
		SimulationConfig.RANDOM_SEED = seeds[NUMBEROFRUNS-1];
		SimulationConfig.RANDOM = new Random(SimulationConfig.RANDOM_SEED);
		
		SimulationConfig.SIMULATION_THREADS = Executors.newScheduledThreadPool(8);
		
		//System.out.println("Selectedseed: " + SimulationConfig.RANDOM_SEED);
		
	//	Config.TRUST_MAX_DEGREE = TRUST_DEGREE;
	//	Config.KEY_SIGNATURE_PARAMETERS = KEY_PARAMETER;
		
		
		Settings scenario = new Settings(SimScenario.SCENARIO_NS);
		//scenario.setSecondaryNamespace(SimScenario.SCENARIO_NS);
		SIMULATION_STEPS = (int) scenario.getDouble(SimScenario.END_TIME_S);
		
		this.nrofGroups = scenario.getInt(SimScenario.NROF_GROUPS_S);
		for(int i = 1; i <= this.nrofGroups ; i++){
			Settings group = new Settings(SimScenario.GROUP_NS+i);
			group.setSecondaryNamespace(SimScenario.GROUP_NS);
			int nrofHostinGroup = group.getInt(SimScenario.NROF_HOSTS_S);
			NETWORK_NUM_DEVICES += nrofHostinGroup;
		}
				
		String suffix = "-d" + TRUST_DEGREE + "-" + KEY_PARAMETER.name()+"-r"+NUMBEROFRUNS;
		//SimulationConfig.METRICS_DATE = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date()) + suffix;
		SimulationConfig.METRICS_DATE = new SimpleDateFormat("yyyyMMdd").format(new Date()) + suffix;
		
		SimulationConfig.METRICS_DIRECTORY = new File(SimulationConfig.METRICS_BASE_DIR, SimulationConfig.METRICS_DATE);
		if (!SimulationConfig.METRICS_DIRECTORY.exists())
			SimulationConfig.METRICS_DIRECTORY.mkdirs();
		
		Metrics.recordConfig();
		
		this.recentNeighbors = new HashMap<DTNHost, Set<DTNHost>>();
		this.random = SimulationConfig.RANDOM;
	
		super.setAppID(APP_ID);
	}

	/**
	 * Copy-constructor
	 *
	 * @param a
	 */
	public AuthenticationApplication(AuthenticationApplication a) {
		super(a);
		
		this.recentNeighbors = new HashMap<DTNHost, Set<DTNHost>>();
		this.random = SimulationConfig.RANDOM;
		
	}

	/**
	 * Handles an incoming message. If the message is a ping message replies
	 * with a pong message. Generates events for ping and pong messages.
	 *
	 * @param msg	message received by the router
	 * @param host	host to which the application instance is attached
	 */
	@Override
	public Message handle(Message msg, DTNHost host) {
		
		if(!isAuthApplication((String)msg.getProperty("type")))
			return null;
		//host.recordMetrics();
		return msg;
	}

	public boolean isAuthApplication(String type){
		if (type==null) 
			return false;
		
		if(!type.equalsIgnoreCase("authentication"))
			return false;
		
		return true;
	}
	
	@Override
	public Application replicate() {
		return new AuthenticationApplication(this);
	}

	/**
	 * Sends a ping packet if this is an active application instance.
	 *
	 * @param host to which the application instance is attached
	 */
	@Override
	public void update(DTNHost host) {
		MessageAuthentication.initialization(host, //null, 
								"M-auth-" + host, 10000);
		
		runSimulation(host);
	}
	
	/**
	 * @param host
	 */
	private void runSimulation(DTNHost host){
		
		host.STEPHOST++;
		
		if((host.STEPHOST % SimulationConfig.METRICS_INITIALIZATION_INTERVAL) == 0)
			host.recordMetrics();
		
		if(!host.isNextStep()){
			//host.recordMetrics();	
			return;
		}
			
		// notify device if neighbors have changed
		Set<DTNHost> neighbors = this.getNeighbors(host);
		if (this.haveNeighborsChanged(host, neighbors))
			host.getReceiver().onNeighborsChanged(neighbors);			

		// skip device if it is already participating in a handshake, or
		// device does not have any neighbors
		if (neighbors.size() == 0){
			//host.recordMetrics();
			return;
		}

		// if device has neighbors, check if a handshake should be
		// performed
		//if (this.random.nextFloat() > SimulationConfig.TRUST_HANDSHAKE_PROB){
			//host.recordMetrics();
			//return;
		//}
		
		// determine partner that is not yet involved in another
		// handshake this round
		DTNHost partner = null;
		Object[] neighborList = neighbors.toArray();
		partner = (DTNHost) neighborList[this.random.nextInt(neighborList.length)];		
	
		Set<DTNHost> neighborsFrom = this.getNeighbors(partner);
		partner.getReceiver().onNeighborsChanged(neighborsFrom);
		
		// perform notify neighbors after updating the neighbors of all(!) devices.
		
		host.getReceiver().notifyNeighbors();			
		this.waitForBackgroundThreads();
		
//		//DeviceLog.d(null, TAG, "### HANDSHAKES ###");
		
//			// perform designated handshakes
		try {
			host.performHandshake(partner);				
		} catch (Exception e) {
			DeviceLog.e(host, TAG, "Could not perform handshake with " + partner, e);
		}		
		this.waitForBackgroundThreads();
		
		if (SimulationConfig.DEBUG_STEPPING_INTERVAL > 0) {
			try {
				Thread.sleep(SimulationConfig.DEBUG_STEPPING_INTERVAL);
			} catch (InterruptedException e) {
				// swallow
			}
		}
	
		host.recordMetrics();		
		host.setTimeBefore(SimClock.getTime());
	}
	
	/**
	 * Waits for all threads to finish the recent work queue.
	 */
	private void waitForBackgroundThreads() {
		// await background threads to finish running tasks
		Future<?> future = null;
		while ((future = SimulationConfig.SIMULATION_FUTURE_QUEUE.poll()) != null) {
			try {
				future.get();
			} catch (Exception e) {
				DeviceLog.e(null, TAG, "Error while awaiting threads to finish!", e);
			}
		}
	}
	
	/**
	 * Gathers all available neighbors for a given device.
	 * 
	 * @param device
	 * @return
	 */
	private Set<DTNHost> getNeighbors(DTNHost device){
		Set<DTNHost> result = new HashSet<>();
		//check each connection this device has with another devices
		for(Connection connection : device.getConnections()){
			//check whether is the same device
			if(device.equals(connection.getOtherNode(device)))
				continue;
			
			result.add(connection.getOtherNode(device));
		}
		return result;
	}
	
	/**
	 * Check if a device's neighbors have changed since the last step.
	 * 
	 * @param device
	 * @param neighbors
	 * @return
	 */
	private boolean haveNeighborsChanged(DTNHost device, Set<DTNHost> neighbors) {
		// Check if there are recent neighbors
		if (!this.recentNeighbors.containsKey(device)) {
			// Update recent neighbors (first entry)
			this.recentNeighbors.put(device, neighbors);
			return true;
		}

		// .equals on a Set
		if (this.recentNeighbors.get(device).equals(neighbors))
			return false;

		this.recentNeighbors.put(device, neighbors);
		return true;
	}

	public void getHostsScenario(){
		this.devices = SimScenario.getInstance().getHosts();
	}
	
	public DTNHost getHostByFingerprint(Fingerprint fingerprint){
		
		for(DTNHost host : this.devices){
			if(host.getFingerprint().equals(fingerprint))
				return host;
		}
		return null;
	}
}
