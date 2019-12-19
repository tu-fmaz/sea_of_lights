package auth_encryption.log;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.UnknownHostException;

public final class Log {
	private static boolean ENABLED = true;
	private static boolean CONSOLE = true;
	private static boolean EXIT_ON_ERROR = false;
	private static File FILE = null;

	public static final int VERBOSE = 2;
	public static final int DEBUG = 3;
	public static final int INFO = 4;
	public static final int WARN = 5;
	public static final int ERROR = 6;
	public static final int ASSERT = 7;

	private Log() {
	}

	public static void setEnabled(boolean enabled) {
		Log.ENABLED = enabled;
	}

	public static void setConsole(boolean enabled) {
		Log.CONSOLE = enabled;
	}
	
	public static void setExitOnError(boolean exit) {
		Log.EXIT_ON_ERROR = exit;
	}

	public static void setFile(File file) {
		Log.FILE = file;
	}

	public static int v(String tag, String msg) {
		return println(VERBOSE, tag, msg);
	}

	public static int v(String tag, String msg, Throwable tr) {
		return println(VERBOSE, tag, msg + '\n' + getStackTraceString(tr));
	}

	public static int d(String tag, String msg) {
		return println(DEBUG, tag, msg);
	}

	public static int d(String tag, String msg, Throwable tr) {
		return println(DEBUG, tag, msg + '\n' + getStackTraceString(tr));
	}

	public static int i(String tag, String msg) {
		return println(INFO, tag, msg);
	}

	public static int i(String tag, String msg, Throwable tr) {
		return println(INFO, tag, msg + '\n' + getStackTraceString(tr));
	}

	public static int w(String tag, String msg) {
		return println(WARN, tag, msg);
	}

	public static int w(String tag, String msg, Throwable tr) {
		return println(WARN, tag, msg + '\n' + getStackTraceString(tr));
	}

	public static int w(String tag, Throwable tr) {
		return println(WARN, tag, getStackTraceString(tr));
	}

	public static int e(String tag, String msg) {
		int r = println(ERROR, tag, msg);
		if (EXIT_ON_ERROR) System.exit(1);
		return r;
	}

	public static int e(String tag, String msg, Throwable tr) {
		int r = println(ERROR, tag, msg + '\n' + getStackTraceString(tr));
		if (EXIT_ON_ERROR) System.exit(1);
		return r;
	}

	public static String getStackTraceString(Throwable tr) {
		if (tr == null) {
			return "";
		}

		// This is to reduce the amount of log spew that apps do in the
		// non-error
		// condition of the network being unavailable.
		Throwable t = tr;
		while (t != null) {
			if (t instanceof UnknownHostException) {
				return "";
			}
			t = t.getCause();
		}

		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		tr.printStackTrace(pw);
		pw.flush();
		return sw.toString();
	}

	public static int println(int priority, String tag, String msg) {
		if (!Log.ENABLED)
			return -1;

		char c = getPriority(priority);
		PrintStream out = System.out;
		if (priority == ERROR)
			out = System.err;

		String line = String.format("%s [%s] %s", c, tag, msg);

		if (Log.CONSOLE)
			out.println(line);

		if (Log.FILE == null)
			return 0;

		try (FileWriter fw = new FileWriter(Log.FILE, true);
				BufferedWriter bw = new BufferedWriter(fw);
				PrintWriter pw = new PrintWriter(bw)) {
			pw.println(line);
		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		}

		return 0;
	}

	private static char getPriority(int priority) {
		switch (priority) {
		case VERBOSE:
			return 'V';
		case DEBUG:
			return 'D';
		case INFO:
			return 'I';
		case WARN:
			return 'W';
		case ERROR:
			return 'E';
		case ASSERT:
			return 'A';
		}

		return 'U';
	}
}
