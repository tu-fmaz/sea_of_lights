/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.modules;

import android.content.Context;

import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * YubiKeyManager class implements Key Manager for using a YubiKey NFC token.
 *
 *@author Max Kolhagen
 */
public class YubiKeyManager extends HardwareKeyManager {
    public static String password = null;

    public YubiKeyManager(Context context, String basePath) {
        super(basePath);

        //throw new UnsupportedOperationException("Not implemented");
    }

    public PublicKey openPublicKey() throws Exception {
        String n = "ccb9207b3f5389ccce5dd1494072185ed69e2a1b51a1e4645de03d7b70cc19f21271ca49dea3a2598aff9e1cbd1fb6ceb1d3304129942d587aa423a867f7f47ccf5547afb5bb3d1b02eb3dc3c87d63152ed20e961659079df61529f371b31d5554ea9910c4963eab8d34ef2ddb26f186b0982382898316649273ebc503936c9839ddd228a9ed12a954dc6d09264f1609ffc2b262bb88d848c29ea154cd82c75582f2d678bc62854c2209f368c1c6f8ec3a29e503e49c7bae622bf7235ff6bd6f9213f6c95b2278ea87cfe95755435639c1c309e5fd38473fcc2cdd3c83ae8c4976787642e2e986ba2401db78fad762fed95fb3063dab45e235fa665ecf123a1f";
        String e = "010001";
        RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(Hex.decode(n)), new BigInteger(Hex.decode(e)));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    public byte[] getAid() throws IOException {
        String info = "00CA004F00";
        return mTransport.transceive(Hex.decode(info));
    }
    /**
     * Puts a key on the token in the given slot.
     *
     * @param secretKey The slot on the token where the key should be stored:
     *             0xB6: Signature Key
     *             0xB8: Decipherment Key
     *             0xA4: Authentication Key
     */
    private void putKey(KeyPair secretKey)
            throws IOException {
        int slot = 0xB6;

        RSAPublicKey pub = (RSAPublicKey) secretKey.getPublic();
        RSAPrivateCrtKey prv = (RSAPrivateCrtKey) secretKey.getPrivate();

        // Shouldn't happen; the UI should block the user from getting an incompatible key this far.
        if (pub.getModulus().bitLength() > 2048) {
            throw new IOException("Key too large to export to Security Token.");
        }

        // Should happen only rarely; all GnuPG keys since 2006 use public exponent 65537.
        if (!pub.getPublicExponent().equals(new BigInteger("65537"))) {
            throw new IOException("Invalid public exponent for smart Security Token.");
        }

        if (!mPw3Validated) {
            verifyPin(0x83); // (Verify PW3 with mode 83)
        }

        byte[] header = Hex.decode(
                "4D82" + "03A2"      // Extended header list 4D82, length of 930 bytes. (page 23)
                        + String.format("%02x", slot) + "00" // CRT to indicate targeted key, no length
                        + "7F48" + "15"      // Private key template 0x7F48, length 21 (decimal, 0x15 hex)
                        + "9103"             // Public modulus, length 3
                        + "928180"           // Prime P, length 128
                        + "938180"           // Prime Q, length 128
                        + "948180"           // Coefficient (1/q mod p), length 128
                        + "958180"           // Prime exponent P (d mod (p - 1)), length 128
                        + "968180"           // Prime exponent Q (d mod (1 - 1)), length 128
                        + "97820100"         // Modulus, length 256, last item in private key template
                        + "5F48" + "820383");// DO 5F48; 899 bytes of concatenated key data will follow
        byte[] dataToSend = new byte[934];
        byte[] currentKeyObject;
        int offset = 0;

        System.arraycopy(header, 0, dataToSend, offset, header.length);
        offset += header.length;
        currentKeyObject = pub.getPublicExponent().toByteArray();
        System.arraycopy(currentKeyObject, 0, dataToSend, offset, 3);
        offset += 3;
        // NOTE: For a 2048-bit key, these lengths are fixed. However, bigint includes a leading 0
        // in the array to represent sign, so we take care to set the offset to 1 if necessary.
        currentKeyObject = prv.getPrimeP().toByteArray();
        System.arraycopy(currentKeyObject, currentKeyObject.length - 128, dataToSend, offset, 128);
        Arrays.fill(currentKeyObject, (byte) 0);
        offset += 128;
        currentKeyObject = prv.getPrimeQ().toByteArray();
        System.arraycopy(currentKeyObject, currentKeyObject.length - 128, dataToSend, offset, 128);
        Arrays.fill(currentKeyObject, (byte) 0);
        offset += 128;
        currentKeyObject = prv.getCrtCoefficient().toByteArray();
        System.arraycopy(currentKeyObject, currentKeyObject.length - 128, dataToSend, offset, 128);
        Arrays.fill(currentKeyObject, (byte) 0);
        offset += 128;
        currentKeyObject = prv.getPrimeExponentP().toByteArray();
        System.arraycopy(currentKeyObject, currentKeyObject.length - 128, dataToSend, offset, 128);
        Arrays.fill(currentKeyObject, (byte) 0);
        offset += 128;
        currentKeyObject = prv.getPrimeExponentQ().toByteArray();
        System.arraycopy(currentKeyObject, currentKeyObject.length - 128, dataToSend, offset, 128);
        Arrays.fill(currentKeyObject, (byte) 0);
        offset += 128;
        currentKeyObject = prv.getModulus().toByteArray();
        System.arraycopy(currentKeyObject, currentKeyObject.length - 256, dataToSend, offset, 256);

        String putKeyCommand = "10DB3FFF";
        String lastPutKeyCommand = "00DB3FFF";

        // Now we're ready to communicate with the token.
        offset = 0;
        String response;
        while (offset < dataToSend.length) {
            int dataRemaining = dataToSend.length - offset;
            if (dataRemaining > 254) {
                response = communicate(
                        putKeyCommand + "FE" + Hex.toHexString(dataToSend, offset, 254)
                );
                offset += 254;
            } else {
                int length = dataToSend.length - offset;
                response = communicate(
                        lastPutKeyCommand + String.format("%02x", length)
                                + Hex.toHexString(dataToSend, offset, length));
                offset += length;
            }

            if (!response.endsWith("9000")) {
                throw new RuntimeException("Key export to Security Token failed" + parseCardStatus(response));
            }
        }

        // Clear array with secret data before we return.
        Arrays.fill(dataToSend, (byte) 0);
    }
}
