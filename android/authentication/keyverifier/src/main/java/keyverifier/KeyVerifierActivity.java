/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package keyverifier;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcelable;
import android.provider.Settings;
import android.support.v7.app.AlertDialog;
import android.support.v4.app.NotificationCompat;
import android.text.InputType;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.ViewTreeObserver;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.Toast;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import keyverifier.R;
import keyverifier.views.FingerprintView;
import primitives.keys.Fingerprint;
import primitives.keys.Signature;

import java.security.PublicKey;
import java.util.Hashtable;
import java.util.Random;

/**
 * KeyVerifierActivity class implements the OoB key verification.
 * Currently supports three authentication mechanisms: visual comparison
 * of fingerprints, scanning QR-Code (using ZXing) and using NFC technology
 *
 *@author Max Kolhagen
 */
public class KeyVerifierActivity extends Activity implements NfcAdapter.OnNdefPushCompleteCallback {
    private static final String TAG = KeyVerifierActivity.class.getSimpleName();
    private static final String PACKAGE = KeyVerifierActivity.class.getPackage().getName();

    /**
     * STATIC IDENTIFIERS
     **/
    public static final String EXTRA_PUBLIC_KEY = PACKAGE + ".extra.publicKey";
    public static final String EXTRA_PUBLIC_KEY_REMOTE = PACKAGE + ".extra.publicKeyRemote";
    public static final String EXTRA_SIGNATURE_REMOTE = PACKAGE + ".extra.signature_remote";
    public static final String EXTRA_PARTNER = PACKAGE + ".extra.fingerprint";
    public static final String EXTRA_RESULT = PACKAGE + ".extra.result";
    public static final String EXTRA_ALIAS = PACKAGE + ".extra.alias";
    public static final String EXTRA_ERROR = PACKAGE + ".extra.error";
    public static final String EXTRA_CODE = PACKAGE + ".extra.code";
    public static final String EXTRA_NOTIFICATION = PACKAGE + ".extra.notification";

    public static final int RESULT_OK = 0;
    public static final int RESULT_ERROR = 1;

    private static final byte ID_FINGERPRINT = 0x01;
    private static final byte ID_FINGERPRINT_REMOTE = 0x02;

    private static final int NOTIFICATION_START = 4200;
    private static final int NOTIFICATION_END = 4300;
    private static final String NOTIFICATION_TITLE = "Key Verification Request";
    private static final String NOTIFICATION_TEST = "Alias: %s, Fingerprint: %s";

    /**
     * INTENT PARAMETERS
     **/
    private PublicKey publicKey = null;
    private PublicKey publicKeyRemote = null;
    private Fingerprint fingerprint = null;
    private Fingerprint fingerprintRemote = null;
    private Signature signatureRemote = null;
    private PendingIntent result = null;

    /**
     * ENCODED FINGERPRINTS
     **/
    private String fingerprint64 = null;
    private String fingerprintRemote64 = null;
    private Bitmap qrCode = null;

    /**
     * NFC FIELDS
     **/
    private NfcAdapter nfcAdapter = null;
    private NdefMessage nfcMessage = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        this.setContentView(R.layout.activity_verify);

        Intent intent = this.getIntent();

        Log.d(TAG, "onCreate - Trying to obtain parameters..." + intent);

        try {
            // get intent parameters
            if (intent.hasExtra(EXTRA_RESULT))
                this.result = intent.getParcelableExtra(EXTRA_RESULT);
            this.publicKey = (PublicKey) intent.getSerializableExtra(EXTRA_PUBLIC_KEY);
            this.publicKeyRemote = (PublicKey) intent.getSerializableExtra(EXTRA_PUBLIC_KEY_REMOTE);
            this.signatureRemote = (Signature) intent.getSerializableExtra(EXTRA_SIGNATURE_REMOTE);

            int id = intent.getIntExtra(EXTRA_NOTIFICATION, -1);
            if (id != -1) {
                Log.d(TAG, "Removing notification again... " + id);
                NotificationManager nManager = (NotificationManager) this.getSystemService(Context.NOTIFICATION_SERVICE);
                nManager.cancel(id);
            }

            if (!this.signatureRemote.verify(this.publicKeyRemote, this.publicKeyRemote))
                throw new IllegalArgumentException("Signature was not valid!");

            // initialize textual fingerprint views
            FingerprintView fpViewMy = (FingerprintView) this.findViewById(R.id.fingerprint_my);
            this.fingerprint = new Fingerprint(this.publicKey);
            fpViewMy.setPublicKey(this.fingerprint);

            FingerprintView fpViewRemote = (FingerprintView) this.findViewById(R.id.fingerprint_remote);
            this.fingerprintRemote = new Fingerprint(this.publicKeyRemote);
            fpViewRemote.setPublicKey(this.fingerprintRemote);

            // encode fingerprints as Base64
            this.fingerprint64 = Base64.encodeToString(this.fingerprint.getData(), Base64.NO_WRAP);
            this.fingerprintRemote64 = Base64.encodeToString(this.fingerprintRemote.getData(), Base64.NO_WRAP);

            // create QR code bitmap and apply it to the image view
            this.qrCode = this.getQRCodeBitmap();
        } catch (Exception e) {
            Log.e(TAG, "onCreate Error", e);
            this.onVerificationError(e);
            this.finish();
            return;
        }

        // initialize NFC adapter and message to push
        this.nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        NdefRecord record = new NdefRecord(
                NdefRecord.TNF_MIME_MEDIA,
                "text/plain".getBytes(),
                new byte[]{ID_FINGERPRINT},
                this.fingerprint64.getBytes());

        NdefRecord recordRemote = new NdefRecord(
                NdefRecord.TNF_MIME_MEDIA,
                "text/plain".getBytes(),
                new byte[]{ID_FINGERPRINT_REMOTE},
                this.fingerprintRemote64.getBytes());

        this.nfcMessage = new NdefMessage(new NdefRecord[]{record, recordRemote});

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH)
            this.nfcAdapter.setNdefPushMessage(this.nfcMessage, this);

        //this.nfcAdapter.setNdefPushMessageCallback(this, this);

        this.nfcAdapter.setOnNdefPushCompleteCallback(this, this);
    }

    /**
     * Create a QR code bitmap from both the given fingerprints
     *
     * @return
     */
    private Bitmap getQRCodeBitmap() {
        try {
            // build QR code bitmap
            Hashtable<EncodeHintType, Object> hints = new Hashtable<>();
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
            BitMatrix result = new QRCodeWriter().encode(this.fingerprint64 + this.fingerprintRemote64, BarcodeFormat.QR_CODE, 0,
                    0, hints);

            int width = result.getWidth();
            int height = result.getHeight();
            int[] pixels = new int[width * height];

            for (int y = 0; y < height; y++) {
                final int offset = y * width;
                for (int x = 0; x < width; x++) {
                    pixels[offset + x] = result.get(x, y) ? Color.BLACK : Color.TRANSPARENT;
                }
            }

            Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
            bitmap.setPixels(pixels, 0, width, 0, 0, width, height);

            return bitmap;
        } catch (WriterException e) {
            Log.e(TAG, "Could not create QR bitmap!", e);
            return null;
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        Log.v(TAG, "onResume");

        // check if NFC (& Android Beam) is enabled
        if (this.nfcAdapter == null || !this.nfcAdapter.isEnabled()) {
            Button btnNFC = (Button) this.findViewById(R.id.button_nfc);
            btnNFC.setText("NFC IS DISABLED!");
            return;
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN &&
                (this.nfcAdapter == null || !this.nfcAdapter.isNdefPushEnabled())) {
            Button btnNFC = (Button) this.findViewById(R.id.button_nfc);
            btnNFC.setText("ANDROID BEAM IS DISABLED!");
            return;
        } else {
            Button btnNFC = (Button) this.findViewById(R.id.button_nfc);
            btnNFC.setText("START NFC VERIFICATION");
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            this.nfcAdapter.enableForegroundNdefPush(this, this.nfcMessage);
            return;
        }

        // prepare reception of NFC messages
        Intent intent = new Intent(this, KeyVerifierActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, 0);

        IntentFilter filter = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        try {
            filter.addDataType("text/plain");
        } catch (IntentFilter.MalformedMimeTypeException e) {
            Log.e(TAG, "Could not add data type to intent filter!", e);
        }

        this.nfcAdapter.enableForegroundDispatch(this, pendingIntent, new IntentFilter[]{filter}, null);
    }

    @Override
    protected void onPause() {
        super.onPause();

        if (this.nfcAdapter == null || !this.nfcAdapter.isEnabled() ||
                (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN && !this.nfcAdapter.isNdefPushEnabled()))
            return;

        // stop listening for NFC events
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            this.nfcAdapter.disableForegroundNdefPush(this);
            return;
        }

        this.nfcAdapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        Log.v(TAG, "onNewIntent - " + intent.getAction());

        if (!NfcAdapter.ACTION_NDEF_DISCOVERED.equals(intent.getAction()))
            return;

        // extract received NFC messages
        NdefMessage[] messages = this.getNdefMessages(intent);
        Log.d(TAG, "onNewIntent - NDEF discovered! " + messages.length);

        if (messages.length == 0)
            return;

        // extract records
        NdefMessage message = messages[0];
        NdefRecord[] records = message.getRecords();

        if (records.length != 2)
            return;

        boolean match = true;
        for (int i = 0; i < records.length || !match; i++) {
            try {
                // compare both own and remote fingerprints
                NdefRecord record = records[i];
                String fingerprint = new String(record.getPayload());

                if (ID_FINGERPRINT == record.getId()[0] && !this.fingerprintRemote64.equals(fingerprint))
                    match = false;
                else if (ID_FINGERPRINT_REMOTE == record.getId()[0] && !this.fingerprint64.equals(fingerprint))
                    match = false;
            } catch (Exception e) {
                Log.d(TAG, "Error comparing fingerprints!", e);
                match = false;
            }
        }

        // give user feedback
        String m = "The NFC tag does not match!!!";
        if (match)
            m = "The NFC tag matches!";

        Toast.makeText(this, m, Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        // check if this is the result of a QR scan
        IntentResult scanResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (scanResult == null) {
            super.onActivityResult(requestCode, resultCode, data);
            return;
        }

        // obtain content of scanned QR code and compare to local fingerprints
        String content = scanResult.getContents();

        String message = "The QR does not match!!!";
        if ((this.fingerprintRemote64 + this.fingerprint64).equals(content))
            message = "The QR code matches!";

        // give user feedback
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

    /**
     * Clicked by the user if the keys are verified and authenticated.
     *
     * @param view
     */
    public void btnMatch_Click(View view) {
        this.showAliasDialog();
    }

    /**
     * Asks the user about an alias for the given remote key.
     */
    private void showAliasDialog() {
        // build AlertDialog
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Select alias...");

        // Set up the input
        final EditText input = new EditText(this);
        String text = "";
        if (this.signatureRemote.getAlias() != null)
            text = this.signatureRemote.getAlias();

        // show suggestion from signature (if available)
        input.setText(text);

        input.setInputType(InputType.TYPE_CLASS_TEXT);
        builder.setView(input);

        // Set up the buttons
        final KeyVerifierActivity context = this;
        builder.setPositiveButton("Confirm", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                context.onVerificationResult(input.getText().toString(), true);
                context.finish();
            }
        });
        builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });

        builder.show();
    }

    /**
     * Clicked by the user if he wants to abort the process or could not verify the keys.
     *
     * @param view
     */
    public void btnCancel_Click(View view) {
        this.onVerificationResult(null, false);
        this.finish();
    }

    /**
     * Trigger visibility of the QR code
     *
     * @param view
     */
    public void btnToggleQR_Click(View view) {
        final ImageView imgFingerprint = (ImageView) this.findViewById(R.id.image_fingerprint);
        final Button btnToggleQR = (Button) this.findViewById(R.id.button_toggle_qr);
        if (imgFingerprint.getVisibility() == View.GONE) {
            imgFingerprint.setVisibility(View.VISIBLE);
            btnToggleQR.setText("Hide QR code");
            imgFingerprint.getViewTreeObserver().addOnGlobalLayoutListener(
                    new ViewTreeObserver.OnGlobalLayoutListener() {
                        @Override
                        public void onGlobalLayout() {
                            // create actual bitmap in display dimensions
                            Bitmap scaled = Bitmap.createScaledBitmap(qrCode,
                                    imgFingerprint.getWidth(), imgFingerprint.getWidth(), false);
                            imgFingerprint.setImageBitmap(scaled);
                        }
                    });
        } else {
            imgFingerprint.setVisibility(View.GONE);
            btnToggleQR.setText("show QR code");
        }
    }

    /**
     * Start Activity for scanning a QR code
     *
     * @param view
     */
    public void btnCheckQR_Click(View view) {
        new IntentIntegrator(this).initiateScan();
    }

    /**
     * Clicked in order to activate/deactivate NFC in the system settings UI.
     *
     * @param view
     */
    public void btnNFC_Click(View view) {
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        this.startActivity(intent);
    }

    /**
     * Helper method for extracting the NFC messages from the given intent.
     *
     * @param intent
     * @return
     */
    private NdefMessage[] getNdefMessages(Intent intent) {
        if (intent == null)
            return null;

        String action = intent.getAction();
        if (!NfcAdapter.ACTION_TAG_DISCOVERED.equals(action)
                && !NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action))
            return null;

        Parcelable[] parcelables = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
        if (parcelables == null || parcelables.length == 0)
            return null;


        NdefMessage[] result = new NdefMessage[parcelables.length];
        for (int i = 0; i < parcelables.length; i++) {
            result[i] = (NdefMessage) parcelables[i];
        }

        return result;
    }

    @Override
    public void onNdefPushComplete(NfcEvent event) {
        Log.v(TAG, "onNdefPushComplete - " + event);
    }

    /**
     * Method called when the verification ended with the user confirming, denying the keys or aborting the process.
     *
     * @param match
     */
    protected void onVerificationResult(String alias, boolean match) {
        if (this.result == null)
            return;

        Log.d(TAG, "onVerificationResult - " + alias);

        try {
            // send result
            final Intent data = new Intent();
            data.putExtra(EXTRA_PARTNER, this.fingerprintRemote);
            data.putExtra(EXTRA_ALIAS, alias);
            data.putExtra(EXTRA_RESULT, match);
            data.putExtra(EXTRA_CODE, RESULT_OK);
            Log.d(TAG, "sending");
            this.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Log.d(TAG, "sending2");
                        KeyVerifierActivity.this.result.send(KeyVerifierActivity.this, RESULT_OK, data);
                        Log.d(TAG, "sending end");
                    } catch (Exception e) {
                        Log.e(TAG, "Error", e);
                    }
                }
            });
        } catch (Exception e) {
            Log.e(TAG, "Unable to send response!", e);
        }
    }

    /**
     * Method called when an exception was raised during the process.
     *
     * @param e
     */
    protected void onVerificationError(Exception e) {
        if (this.result == null)
            return;

        try {
            // send result
            Intent data = new Intent();
            data.putExtra(EXTRA_PARTNER, this.fingerprintRemote);
            data.putExtra(EXTRA_ERROR, e);
            data.putExtra(EXTRA_CODE, RESULT_ERROR);
            this.result.send(this, RESULT_ERROR, data);
        } catch (Exception err) {
            Log.e(TAG, "Unable to send response!", err);
        }
    }

    // ---- START THE VERIFICATION

    /**
     * Will start the KeyVerifierActivity with the given parameters.
     *
     * @param context
     * @param publicKey       The local (own) public key which was sent to the remote device.
     * @param publicKeyRemote The remote public key which was received during the handshake protocol.
     */
    public static void performKeyVerification(Context context, PublicKey publicKey, PublicKey publicKeyRemote, Signature signatureRemote, PendingIntent result) {
        Log.d(TAG, "performKeyVerification - Starting key verification activity");

        Intent intent = buildIntent(context, publicKey, publicKeyRemote, signatureRemote, result);
        context.startActivity(intent);
    }

    /**
     * Shows a notification that a key needs to be verified. There may be multiple notifications.
     *
     * @param context
     * @param publicKey
     * @param publicKeyRemote
     * @param signatureRemote
     * @param result
     */
    public static void showNotification(Context context, PublicKey publicKey, PublicKey publicKeyRemote, Signature signatureRemote, PendingIntent result) {
        // generate a random notification ID
        Random random = new Random();
        int id = random.nextInt(NOTIFICATION_END - NOTIFICATION_START + 1) + NOTIFICATION_START;

        Log.d(TAG, "Notification ID = " + id);

        // build intent
        Intent intent = buildIntent(context, publicKey, publicKeyRemote, signatureRemote, result);
        intent.putExtra(EXTRA_NOTIFICATION, id);
        PendingIntent pending = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_CANCEL_CURRENT);

        String text = "click here to validate...";
        try {
            text = String.format(NOTIFICATION_TEST, signatureRemote.getAlias(), signatureRemote.getSubject().toString());
        } catch (Exception e) {
            Log.e(TAG, "Error", e);
        }

        // show notification
        Notification n = new NotificationCompat.Builder(context)
                .setSmallIcon(R.drawable.ic_swap_horiz_black_24dp)
                .setContentIntent(pending)
                .setContentTitle(NOTIFICATION_TITLE)
                .setContentText(text).build();

        NotificationManager nManager = (NotificationManager) context.getSystemService(NOTIFICATION_SERVICE);
        nManager.notify(id, n);
    }

    /**
     * Build intent to start the key verification with the given parameters.
     *
     * @param context
     * @param publicKey
     * @param publicKeyRemote
     * @param signatureRemote
     * @param result
     * @return
     */
    private static Intent buildIntent(Context context, PublicKey publicKey, PublicKey publicKeyRemote, Signature signatureRemote, PendingIntent result) {
        Intent intent = new Intent(context, KeyVerifierActivity.class);
        intent.putExtra(EXTRA_PUBLIC_KEY, publicKey);
        intent.putExtra(EXTRA_PUBLIC_KEY_REMOTE, publicKeyRemote);
        intent.putExtra(EXTRA_SIGNATURE_REMOTE, signatureRemote);
        if (result != null)
            intent.putExtra(EXTRA_RESULT, result);
        return intent;
    }
}
