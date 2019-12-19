package auth_encryption.simulator;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

import org.apache.commons.io.FileUtils;

import com.google.gson.GsonBuilder;

import applications.AuthenticationApplication;
import auth_encryption.primitives.Config;
import core.DTNHost;
import core.SimClock;

/**
 * Class responsible for recording all device specific metrics.
 * PROPAGATION = T, MEMORY = M, BANDWIDTH = B, PERFORMANCE = P
 * MemoryTypes: PUBLIC KEYS = PK, SIGNATURES = SIG, SUB_KEYS = SK, SUB_KEYS_SIGNATURE = SKSIG
 * BandwidthTypes: SYNC_QUERY = QRY, SYNC_RESPONSE = RSP
 * PerformanceTypes: NUM_VERIFICATIONS = V, NUM_SIGNATURES = S, TIME_INITIALIZATION = I
 */
public final class Metrics {
	private static final String TAG = Metrics.class.getSimpleName();

	static {
		// record the configurations at the beginning of a simulation
		Metrics.recordConfig();
	}

	private Metrics() {
		// hide
	}

	// ----

	/**
	 * Constants for the types of metrics
	 */
	public interface Category {
		public static final String INITIALIZATION = "I";
		public static final String PROPAGATION = "T";
		public static final String MEMORY = "M";
		public static final String BANDWIDTH = "B";
		public static final String PERFORMANCE = "P";
		public static final String MESSAGE = "M";
	}

	/*
	 * Wrapper methods
	 */

	public static void recordInitialization(DTNHost d) {
		Metrics.recordMetric(d, Category.INITIALIZATION, d.getUUID() + "/" + d.getFingerprint(), 0.0f);
	}

	// ----
	
	public interface MessageType{
		public static final String SYNC = "SYNC";
		public static final String SYNC_REQUEST = "SYNC_REQUEST";
		public static final String HS_INIT = "HS_INIT";
		public static final String HS_SIG = "HS_SIG";
	}
	
	public static void recordMessage(DTNHost d, String messageType, double v) {
		// Parameters p = new Parameters();
		// p.put("type", memoryType);
		Metrics.recordMetric(d, Category.MESSAGE, messageType, v);
	}
	
	// ----

	public static void recordTotalPropagation(DTNHost d, long v) {
		Metrics.recordMetric(d, Category.PROPAGATION, 0, v);
	}

	public static void recordDirectPropagation(DTNHost d, long v) {
		// Parameters p = new Parameters();
		// p.put("degree", 1);
		Metrics.recordMetric(d, Category.PROPAGATION, 1, v);
	}

	public static void recordIndirectPropagation(DTNHost d, long v) {
		// Parameters p = new Parameters();
		// p.put("degree", 2);
		Metrics.recordMetric(d, Category.PROPAGATION, 2, v);
	}

	// ----

	public interface MemoryType {
		public static final String TOTAL = "TOTAL";
		public static final String PUBLIC_KEYS = "PK";
		public static final String SIGNATURES = "SIG";
		public static final String SUB_KEYS = "SK";
		public static final String SUB_KEY_SIGNATURES = "SKSIG";
	}

	public static void recordSizeTrustDirectory(DTNHost d, String memoryType, double v) {
		// Parameters p = new Parameters();
		// p.put("type", memoryType);
		Metrics.recordMetric(d, Category.MEMORY, memoryType, v);
	}

	// ----

	public interface BandwidthType {
		public static final String TOTAL = "TOTAL";
		public static final String SYNC_QUERY = "QRY";
		public static final String SYNC_RESPONSE = "RSP";
	}

	public static void recordSynchronizationBandwidth(DTNHost d, String syncType, double v) {
		// Parameters p = new Parameters();
		// p.put("type", syncType);
		Metrics.recordMetric(d, Category.BANDWIDTH, syncType, v);
	}

	// ----

	public interface PerformanceType {
		public static final String NUM_VERIFICATIONS = "V";
		public static final String NUM_SIGNATURES = "S";
		public static final String TIME_INITIALIZATION = "I";
	}

	public static void recordPerformance(DTNHost d, String performanceType, double v) {
		// Parameters p = new Parameters();
		// p.put("type", performanceType);
		Metrics.recordMetric(d, Category.PERFORMANCE, performanceType, v);
	}

	// ----

	/**
	 * Records a single datum metric for the given device.
	 * 
	 * @param d Device
	 * @param c Category
	 * @param p Parameter/Type
	 * @param v Actual value
	 */
	private static void recordMetric(DTNHost d, String c, Object p, double v) {
		final String prefix = SimulationConfig.METRICS_DATE + "-";
		
		//final File file = new File(SimulationConfig.METRICS_DIRECTORY, prefix + d.getUUID() + ".csv");
		final File file = new File(SimulationConfig.METRICS_DIRECTORY, prefix + d.getUUID()+"-"+d.toString() + ".csv");

		// create/append to the file
		try (FileWriter fw = new FileWriter(file, true);
				BufferedWriter bw = new BufferedWriter(fw);
				PrintWriter out = new PrintWriter(bw)) {
			//out.print(Simulator.STEP);
			int step = d.STEPHOST ;/// 10;						
			int precision = 2;
			String duration = String.format("%." + precision + "f", SimClock.getTime());
			//DeviceLog.d(null, TAG, "duration: "+duration);
			out.print(duration);
			out.print(";");
			out.print(step);
			out.print(";");
			out.print(c);
			out.print(";");
			out.print(p);
			out.print(";");
			out.print(v);
			out.println();
		} catch (IOException e) {
			DeviceLog.e(null, TAG, "Error writing metrics file!", e);
		}
	}

	/**
	 * Writes the current configuration to the metrics file.
	 */
	public static void recordConfig() {
		File file = new File(SimulationConfig.METRICS_DIRECTORY,
				SimulationConfig.METRICS_DATE + "-CONFIG.json");

		try {
			// Serialize the config class using JSON.
			
			GsonBuilder gsonBuilder = new GsonBuilder();
			// Allowing the serialization of static fields
			gsonBuilder.excludeFieldsWithModifiers(java.lang.reflect.Modifier.TRANSIENT);

			String json = gsonBuilder.create().toJson(new SimulationConfig());
			Files.write(file.toPath(), json.getBytes(), StandardOpenOption.CREATE);
		} catch (IOException e) {
			DeviceLog.e(null, TAG, "Unable to write config settings!", e);
		}
	}

	/**
	 * Clear the entire metrics directory (CAUTION: cannot be reverted!)
	 */
	private static void clear() {
		try {
			System.err.println("Cleaning entire(!) metrics directory in 5 sec!");
			Thread.sleep(5000);
			FileUtils.deleteDirectory(SimulationConfig.METRICS_BASE_DIR);
			System.out.println("Done...");
		} catch (Exception e) {
			DeviceLog.e(null, TAG, "Unable to clear metrics directory!", e);
		}
	}

	// ----

	public static void main(String[] args) {
		Metrics.clear();
	}
}
