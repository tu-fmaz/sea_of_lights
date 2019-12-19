/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.helper;

import java.io.File;

/**
 * Utils class implements utility methods.
 *
 *@author Max Kolhagen
 */
public class Utils {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * Converts bytes to a hexadecimal string.
     *
     * @param bytes
     * @return
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX[v >>> 4];
            hexChars[j * 2 + 1] = HEX[v & 0x0F];
        }

        return new String(hexChars);
    }

    /**
     * Converts a hexadecimal string into the corresponding bytes.
     *
     * @param hex
     * @return
     */
    public static byte[] hexToBytes(String hex) {
        String value = hex;
        /*if (value.length() % 2 == 1) value = "0" + value;

		// cut off leading 0s
		int cutOff = 0;
		while (hex.startsWith("00", cutOff))
			cutOff += 2;
		if (cutOff < value.length())
			value = value.substring(cutOff);
		 */
        int len = value.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int c1 = Character.digit(value.charAt(i), 16);
            int c2 = Character.digit(value.charAt(i + 1), 16);
            if (c1 == -1 || c2 == -2)
                throw new IllegalArgumentException("Illegal hex characters!");
            data[i / 2] = (byte) ((c1 << 4) + c2);
        }
        return data;
    }

    /**
     * Converts an Integer into its byte representation.
     *
     * @param value
     * @return
     */
    public static byte[] intBytes(int value) {
        byte[] result = new byte[4];
        result[0] = (byte) (value >>> 24);
        result[1] = (byte) (value >>> 16);
        result[2] = (byte) (value >>> 8);
        result[3] = (byte) (value);
        return result;
    }

    /**
     * Recursively deletes a directory.
     *
     * @param file
     */
    public static void deleteDirectory(File file) {
        if (file.isDirectory())
            for (File child : file.listFiles())
                deleteDirectory(child);

        file.delete();
    }

    /**
     * Determines the n LSB of an Integer.
     *
     * @param value
     * @param n
     * @return
     */
    public static long getLeastSignificantBits(long value, int n) {
        return value & ((1 << n) - 1);
    }
}
