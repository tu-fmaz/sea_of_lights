/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.modules;

import android.content.Context;
import android.util.Log;

import org.simalliance.openmobileapi.Channel;
import org.simalliance.openmobileapi.Reader;
import org.simalliance.openmobileapi.SEService;
import org.simalliance.openmobileapi.Session;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;

/**
 * SeekKeyManager class implements Key Manager for using SEEKforAndroid framework.
 * for more details see http://seek-for-android.github.io
 *
 *@author Max Kolhagen
 */
public class SeekKeyManager extends HardwareKeyManager implements SEService.CallBack {
    // Constant for logging
    private static final String TAG = SeekKeyManager.class.getSimpleName();


    public static String password = null;

    private SEService service = null;

    public SeekKeyManager(Context context, String basePath) {
        super(basePath);

        //throw new UnsupportedOperationException("Not implemented");
        try {
            this.service = new SEService(context, this);
        } catch (SecurityException e) {
            Log.e(TAG, "Binding not allowed, uses-permission org.simalliance.openmobileapi.SMARTCARD?");
        } catch (Exception e) {
            Log.e(TAG, "Exception: " + e.getMessage());
        }
    }

    @Override
    public void serviceConnected(SEService seService) {
        this.service = seService;
    }

    public byte[] getAid() throws IOException {
        String info = "00CA004F02";
        return mTransport.transceive(Hex.decode(info));
    }

    /**
     * Check if permissions for smartcard-reader is available
     * */
    public static boolean isSeekAvailable(Context context) {
        try {
            SEService service = new SEService(context, null);
            return (getAvailableReaders(service) != null);
        } catch (SecurityException e) {
            Log.e(TAG, "Binding not allowed, uses-permission org.simalliance.openmobileapi.SMARTCARD?");
        } catch (Exception e) {
            Log.e(TAG, "Exception: " + e.getMessage());
        }

        return false;
    }

    /**
     * Get available readers from the device
     * */
    public static Reader getAvailableReaders(SEService service) {
        if (service == null)
            return null;

        try {
            Log.i(TAG, "Retrieve available readers...");
            Reader[] readers = service.getReaders();
            if (readers.length < 1)
                return null;

            for (Reader reader : readers) {
                try {
                    Log.i(TAG, "Create Session from the first reader...");
                    Session session = reader.openSession();

                    Log.i(TAG, "Create logical channel within the session...");
                    Channel channel = session.openLogicalChannel(new byte[]{
                            (byte) 0xD2, 0x76, 0x00, 0x01, 0x18, 0x00, 0x02,
                            (byte) 0xFF, 0x49, 0x50, 0x25, (byte) 0x89,
                            (byte) 0xC0, 0x01, (byte) 0x9B, 0x01});

                    Log.i(TAG, "Send HelloWorld APDU command");
                    byte[] respApdu = channel.transmit(new byte[]{
                            (byte) 0x90, 0x10, 0x00, 0x00, 0x00});

                    channel.close();

                    // Parse response APDU and show text but remove SW1 SW2 first
                    byte[] helloStr = new byte[respApdu.length - 2];
                    System.arraycopy(respApdu, 0, helloStr, 0, respApdu.length - 2);
                    Log.d(TAG, new String(helloStr));
                    return reader;
                } catch (Exception e) {
                    Log.e(TAG, "error", e);
                    continue;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error occured:", e);
        }

        return null;
    }
}
