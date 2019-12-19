package auth_encryption.simulator;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.ObjectOutputStream;
import java.util.Random;

import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.Clip;
import javax.sound.sampled.DataLine;

import org.apache.commons.io.FileUtils;

/**
 * Globally required utilities.
 */
public final class SimulationUtils {
	private SimulationUtils() {
		// hide
	}

	/**
	 * Generate a random UUID in a specific format and length.
	 * 
	 * @return
	 */
	public static String getUUID() {
		final Random random = SimulationConfig.RANDOM;
		final StringBuilder result = new StringBuilder();

		// append alphanumerical character for a specific length
		for (int i = 0; i < SimulationConfig.DEBUG_UUID_LENGTH; i++) {
			int a = random.nextInt(36);

			char c = (char) (a + 65);
			if (a >= 26)
				c = (char) (a - 26 + 48);

			result.append(c);

		}

		return result.toString();
	}

	/**
	 * Returns the actual size of a given directory and optionally applies a
	 * filter on the files to be considered.
	 * 
	 * @param directory
	 * @param filter
	 * @return
	 */
	public static long directorySize(File directory, FileFilter filter) {
		long length = 0;
		File[] files = (filter != null) ? directory.listFiles(filter) : directory.listFiles();
		for (File file : files) {
			if (file.isFile()) {
				// System.out.println("- " + file.getAbsolutePath());
				length += file.length();
			} else {
				length += directorySize(file, filter);
			}
		}
		return length;
	}

	/**
	 * Returns the size of a Java serialized object (how they would be sent over
	 * the network with our solution).
	 * 
	 * @param object
	 * @return
	 */
	public static long getNetworkObjectSize(Object object) {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(object);
			oos.close();
			return baos.size();
		} catch (Exception e) {
			e.printStackTrace();
			return 0;
		}
	}

	private static final String SOUND_DIR = "sounds/";
	private static final long SOUND_DELAY = 500;

	public static synchronized void playSound(final String file, int rounds) {
		for (int i = 0; i < rounds; i++) {
			playSound(file);

			if (i == (rounds - 1))
				continue;

			try {
				Thread.sleep(SOUND_DELAY);
			} catch (Exception e) {
				// ...
			}
		}
	}

	public static synchronized void playSound(final String file) {
		try {
			// specify the sound to play
			// (assuming the sound can be played by the audio system)
			File soundFile = new File(SOUND_DIR + file);
			AudioInputStream sound = AudioSystem.getAudioInputStream(soundFile);

			// load the sound into memory (a Clip)
			DataLine.Info info = new DataLine.Info(Clip.class, sound.getFormat());
			Clip clip = (Clip) AudioSystem.getLine(info);
			clip.open(sound);

			// due to bug in Java Sound, explicitly exit the VM when
			// the sound has stopped.
			/*
			 * clip.addLineListener(new LineListener() {
			 * public void update(LineEvent event) {
			 * if (event.getType() == LineEvent.Type.STOP) {
			 * event.getLine().close();
			 * System.exit(0);
			 * }
			 * }
			 * });
			 */

			// play the sound clip
			clip.start();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// ----

	public static void main(String[] args) {
		final File trustDir = new File("simulation/1BK9/trust");
		System.out.println("Directory = " + trustDir.getAbsolutePath() + ", " + trustDir.exists());

		System.out.println(FileUtils.sizeOfDirectory(trustDir));

		System.out.println("--- TOTAL");
		System.out.println(SimulationUtils.directorySize(trustDir, null));

		System.out.println("--- PK");
		System.out.println(SimulationUtils.directorySize(trustDir, new FileFilter() {
			@Override
			public boolean accept(File pathname) {
				if (pathname.isDirectory())
					return true;

				return pathname.getAbsolutePath().endsWith("/keys/public.key");
			}
		}));

		System.out.println("--- SIG");
		System.out.println(SimulationUtils.directorySize(trustDir, new FileFilter() {
			@Override
			public boolean accept(File pathname) {
				if (pathname.isDirectory())
					return true;

				if (pathname.getParent().endsWith("/keys"))
					return false;

				return pathname.getName().endsWith(".sig");
			}
		}));

		System.out.println("--- SK");
		System.out.println(SimulationUtils.directorySize(trustDir, new FileFilter() {
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

		System.out.println("--- SKSIG");
		System.out.println(SimulationUtils.directorySize(trustDir, new FileFilter() {
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
}
