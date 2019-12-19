package auth_encryption.simulator;

import org.apache.commons.lang3.StringUtils;

import auth_encryption.log.Log;
import core.DTNHost;

/**
 * Class for device-specific logging. Forwards to the actual logging class.
 */
public final class DeviceLog {
	/*
	 * Number of digits necessary to display all steps (for formatting)
	 */
	private static int NUM_DIGITS = (int) Math.ceil(Math.log10(SimulationConfig.SIMULATION_STEPS));
	public static int STEP = 0;

	private DeviceLog() {
		// hide
	}
	
	/*
	 * Wrapper methods
	 */

	public static void v(DTNHost device, String tag, String message) {
		Log.d(getTag(device, tag), message);
	}

	public static void d(DTNHost device, String tag, String message) {
		Log.d(getTag(device, tag), message);
	}

	public static void i(DTNHost device, String tag, String message) {
		Log.d(getTag(device, tag), message);
	}

	public static void w(DTNHost device, String tag, String message) {
		Log.w(getTag(device, tag), message);
	}

	public static void w(DTNHost device, String tag, String message, Throwable error) {
		Log.w(getTag(device, tag), message, error);
	}

	public static void e(DTNHost device, String tag, String message) {
		Log.e(getTag(device, tag), message);
	}

	public static void e(DTNHost device, String tag, String message, Throwable error) {
		Log.w(getTag(device, tag), message, error);
	}

	/**
	 * Builds the tag for the given device.
	 * 
	 * @param device
	 * @param tag
	 * @return
	 */
	public static String getTag(DTNHost device, String tag) {
		String prefix = "";
		if (SimulationConfig.DEBUG_LOG_INCLUDE_STEP)
			prefix = "#" ;//+ StringUtils.leftPad("" + STEP , NUM_DIGITS, '0') + " ";

		if (device == null)
			return prefix + tag;
		
		//return prefix + device.toString() + " " + tag;
		/////////////////////////////////////////////
		return prefix + device + " " + tag;
		/////////////////////////////////////////////
	}
}
