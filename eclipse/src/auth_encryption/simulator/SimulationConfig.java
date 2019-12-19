package auth_encryption.simulator;

import java.io.File;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import applications.AuthenticationApplication;
import auth_encryption.primitives.Config;
import core.SimScenario;

public class SimulationConfig implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/*
	 * private SimulationConfig() { }
	 */

	/*
	 * Network
	 */

	public static final int NETWORK_DIMENSION = 250;
	
	////////////////////////////////////////////////
	//public static final int NETWORK_NUM_DEVICES = 50;
	//public static final int NETWORK_NUM_DEVICES = AuthenticationApplication.NETWORK_NUM_DEVICES;
	public static final int NETWORK_NUM_DEVICES = 120;
	////////////////////////////////////////////////
	
	public static final int NETWORK_SEND_DELAY = 1;

	/*
	 * Device configuration for the simulation without ONE
	 */

	public static final int DEVICE_TRANSMISSION_RANGE = 10;
	public static final float DEVICE_MOVEMENT_PROB = 0.75f;
	public static final int DEVICE_VELOCITY_MIN = 1;
	public static final int DEVICE_VELOCITY_MAX = 20;

	/*
	 * Trust
	 */

	public static final float TRUST_HANDSHAKE_PROB = 0.5f;
	public static final int TRUST_SUBKEYS_MIN = 0;
	public static final int TRUST_SUBKEYS_MAX = 3;
	public static final int TRUST_SIZE_SUBKEY = 512; // in bytes

	/*
	 * Simulation
	 */

	//public static final int SIMULATION_STEPS = AuthenticationApplication.SIMULATION_STEPS; // total number of steps
	public static final int SIMULATION_STEPS = 43200; // total number of steps
	public static String SIMULATION_PATH = "simulation/";
	public static transient ExecutorService SIMULATION_THREADS = Executors.newScheduledThreadPool(8);
	public static final transient Queue<Future<?>> SIMULATION_FUTURE_QUEUE = new ConcurrentLinkedQueue<>();

	public static long RANDOM_SEED;
	public static transient Random RANDOM = new Random();

	/*
	 * Debugging
	 */

	public static final long DEBUG_STEPPING_INTERVAL = 0; // delay between steps
	public static final int DEBUG_UUID_LENGTH = 4;
	public static final boolean DEBUG_DRAW_MAP = false;
	public static final boolean DEBUG_LOG_ENABLED = true;
	public static final boolean DEBUG_LOG_FILE = true; // log to file
	public static final boolean DEBUG_LOG_CONSOLE = false; // log to console
	public static final boolean DEBUG_LOG_INCLUDE_STEP = true; // indicate current step
	public static final boolean DEBUG_EXIT_ON_ERROR = false;

	/*
	 * Metrics for measurement of bandwidth, memory, performance
	 */

	//public static String METRICS_DATE = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
	public static String METRICS_DATE = new SimpleDateFormat("yyyyMMdd").format(new Date());
	public static final transient File METRICS_BASE_DIR = new File("metrics/");
	public static transient File METRICS_DIRECTORY = new File(SimulationConfig.METRICS_BASE_DIR,
			SimulationConfig.METRICS_DATE);
	public static final int METRICS_INITIALIZATION_INTERVAL = 60; // how often to reinitialize the repository

	/*
	 * Initialization
	 */

	static {
		// create metrics directory if it does not exist
		//if (!METRICS_DIRECTORY.exists())
		//	METRICS_DIRECTORY.mkdirs();

		// randomly seed the random object
		RANDOM_SEED = RANDOM.nextLong();
		RANDOM.setSeed(RANDOM_SEED);

		// initialize the logging class
		//Log.setEnabled(DEBUG_LOG_ENABLED);
		//Log.setConsole(DEBUG_LOG_CONSOLE);
		//Log.setExitOnError(DEBUG_EXIT_ON_ERROR);
		//if (DEBUG_LOG_FILE)
			//Log.setFile(new File(METRICS_DIRECTORY, METRICS_DATE + ".log"));
	}
	
	public static long[] fillSeeds(int runs){
		long[] seeds = new long[runs];
		Random random = new Random();
		for(int s=0;s < seeds.length; s++)
			seeds[s] = random.nextLong();
		
		return seeds;
	}
}
