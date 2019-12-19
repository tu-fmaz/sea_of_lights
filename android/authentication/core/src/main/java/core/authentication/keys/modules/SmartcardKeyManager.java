/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.modules;

import android.content.Context;

import core.authentication.keys.interaction.NFCSignatureActivity;
import primitives.helper.AppDetails;
import primitives.keys.Signature;
import primitives.keys.SubKeySignature;

import org.spongycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.PublicKey;

/**
 * SmartcardKeyManager class implements Key Manager for using  NFC smart cards.
 *
 *@author Max Kolhagen
 */
public class SmartcardKeyManager extends HardwareKeyManager {
    public static String password = null;

    /**
     * Constructor
     * */
    public SmartcardKeyManager(Context context, String basePath) {
        super(basePath);
    }

    public byte[] getAid() throws IOException {
        String info = "00CA004F01";
        return mTransport.transceive(Hex.decode(info));
    }

    @Override
    protected byte[] sign(byte[] data) throws Exception {
        return null;
    }

    @Override
    public Signature createSignature(PublicKey subject, String alias) throws Exception {
        Signature signature = super.createSignature(subject, alias);

        // add to signature queue
        NFCSignatureActivity.SignatureQueue.getInstance(null).addSignature(null, signature);

        return null;
    }

    @Override
    public SubKeySignature createSubKeySignature(byte[] subKey, AppDetails appDetails, boolean bindToApp, String tag) throws Exception {
        SubKeySignature signature = super.createSubKeySignature(subKey, appDetails, bindToApp, tag);

        // add to signature queue
        NFCSignatureActivity.SignatureQueue.getInstance(null).addSignature(null, signature);

        return null;
    }
}
