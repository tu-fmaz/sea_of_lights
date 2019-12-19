/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.modules;

import android.util.Log;

import core.authentication.keys.KeyManager;

import org.spongycastle.util.encoders.Hex;

import java.io.IOException;

import nordpol.IsoCard;

/**
 * HardwareKeyManager class Abstract hardware based key manager. Providing APDU communication utils to its children classes.
 *
 *@author Max Kolhagen
 */
public abstract class HardwareKeyManager extends KeyManager {
    // Constant for logging
    private static final String TAG = HardwareKeyManager.class.getSimpleName();

    protected IsoCard mTransport = null;

    // Local variables for managing PW Status Bytes
    protected boolean mPw1ValidForMultipleSignatures;
    protected boolean mPw1ValidatedForSignature;
    protected boolean mPw1ValidatedForDecrypt; // Mode 82 does other things; consider renaming?
    protected boolean mPw3Validated;

    // Local variables for setting pin
    private String mUserPin = "123457";
    private String mAdminPin = "52041682";
    /**
     * Constructor
     * */
    public HardwareKeyManager(String basePath) {
        super(basePath);
    }

    public void initialize() {
        try {
            this.mTransport.setTimeout(100 * 1000);
            this.mTransport.connect();
            this.connectToDevice();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    /**
     * Connect to device and select pgp applet
     *
     * @throws IOException
     */
    public void connectToDevice() throws IOException {
        // Connect on transport layer
        //mTransport.connect();

        // Connect on smartcard layer

        // SW1/2 0x9000 is the generic "ok" response, which we expect most of the time.
        // See specification, page 51
        String accepted = "9000";

        // Command APDU (page 51) for SELECT FILE command (page 29)
        String opening =
                "00" // CLA
                        + "A4" // INS
                        + "04" // P1
                        + "00" // P2
                        + "06" // Lc (number of bytes)
                        + "D27600012401" // Data (6 bytes)
                        + "00"; // Le
        String response = communicate(opening);  // activate connection
        if (!response.endsWith(accepted)) {
            throw new RuntimeException("Initialization failed!" +  parseCardStatus(response));
        }

        byte[] pwStatusBytes = getPwStatusBytes();
        mPw1ValidForMultipleSignatures = (pwStatusBytes[0] == 1);
        mPw1ValidatedForSignature = false;
        mPw1ValidatedForDecrypt = false;
        mPw3Validated = false;
    }

    private static String getHex(byte[] raw) {
        return new String(Hex.encode(raw));
    }

    public byte[] calculateSignature(byte[] hash) throws IOException {
        if (!mPw1ValidatedForSignature) {
            verifyPin(0x81); // (Verify PW1 with mode 81 for signing)
        }

        // dsi, including Lc
        String dsi;

        if (hash.length != 32) {
            throw new IOException("Bad hash length (" + hash.length + ", expected 32!");
        }
        dsi = "333031300D060960864801650304020105000420" + getHex(hash);


        // Command APDU for PERFORM SECURITY OPERATION: COMPUTE DIGITAL SIGNATURE (page 37)
        String apdu =
                "002A9E9A" // CLA, INS, P1, P2
                        + dsi // digital signature input
                        + "00"; // Le

        String response = communicate(apdu);

        if (response.length() < 4) {
            throw new RuntimeException("Bad response");
        }
        // split up response into signature and status
        String status = response.substring(response.length() - 4);
        String signature = response.substring(0, response.length() - 4);

        // while we are getting 0x61 status codes, retrieve more data
        while (status.substring(0, 2).equals("61")) {
            Log.d(TAG, "requesting more data, status " + status);
            // Send GET RESPONSE command
            response = communicate("00C00000" + status.substring(2));
            status = response.substring(response.length() - 4);
            signature += response.substring(0, response.length() - 4);
        }

        Log.d(TAG, "final response:" + status);

        if (!mPw1ValidForMultipleSignatures) {
            mPw1ValidatedForSignature = false;
        }

        if (!"9000".equals(status)) {
            throw new RuntimeException("Bad NFC response code: " + status +  parseCardStatus(response));
        }

        // Make sure the signature we received is actually the expected number of bytes long!
        if (signature.length() != 256 && signature.length() != 512
                && signature.length() != 768 && signature.length() != 1024) {
            throw new IOException("Bad signature length! Expected 128/256/384/512 bytes, got " + signature.length() / 2);
        }

        return Hex.decode(signature);
    }

    private String getDataField(String output) {
        return output.substring(0, output.length() - 4);
    }
    /**
     * Verifies the user's PW1 or PW3 with the appropriate mode.
     *
     * @param mode For PW1, this is 0x81 for signing, 0x82 for everything else.
     *             For PW3 (Admin PIN), mode is 0x83.
     */
    protected void verifyPin(int mode) throws IOException {
        if (mUserPin != null || mode == 0x83) {

            byte[] pin;
            if (mode == 0x83) {
                pin = new String(mAdminPin).getBytes();
            } else {
                pin = new String(mUserPin).getBytes();
            }

            // SW1/2 0x9000 is the generic "ok" response, which we expect most of the time.
            // See specification, page 51
            String accepted = "9000";
            String response = tryPin(mode, pin); // login
            if (!response.equals(accepted)) {
                throw new RuntimeException("Bad PIN!" + parseCardStatus(response));
            }

            if (mode == 0x81) {
                mPw1ValidatedForSignature = true;
            } else if (mode == 0x82) {
                mPw1ValidatedForDecrypt = true;
            } else if (mode == 0x83) {
                mPw3Validated = true;
            }
        }
    }
    /**
     * Parses out the status word from a JavaCard response string.
     *
     * @param response A hex string with the response from the card
     * @return A short indicating the SW1/SW2, or 0 if a status could not be determined.
     */
    protected short parseCardStatus(String response) {
        if (response.length() < 4) {
            return 0; // invalid input
        }

        try {
            return Short.parseShort(response.substring(response.length() - 4), 16);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
    /**
     * Transceive data via NFC encoded as Hex
     */
    protected String communicate(String apdu) throws IOException {
        return getHex(mTransport.transceive(Hex.decode(apdu)));
    }

    /**
     * Return the PW Status Bytes from the token. This is a simple DO; no TLV decoding needed.
     *
     * @return Seven bytes in fixed format, plus 0x9000 status word at the end.
     */
    private byte[] getPwStatusBytes() throws IOException {
        String data = "00CA00C400";
        return mTransport.transceive(Hex.decode(data));
    }

    private String tryPin(int mode, byte[] pin) throws IOException {
        // Command APDU for VERIFY command (page 32)
        String login =
                "00" // CLA
                        + "20" // INS
                        + "00" // P1
                        + String.format("%02x", mode) // P2
                        + String.format("%02x", pin.length) // Lc
                        + Hex.toHexString(pin);

        return communicate(login);
    }
}
