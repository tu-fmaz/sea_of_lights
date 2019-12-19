
/**
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package core.authentication.keys.interaction;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v4.app.NotificationCompat;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import core.authentication.R;
import core.authentication.keys.KeyManagerPriority;

/**
 * PinDialogActivity class Transparent Activity Dialog for entering the PIN to a keystore.
 *
 *@author Max Kolhagen
 */
public class PinDialogActivity extends Activity {

    // Constants for logging and intent extra
    private static final String TAG = PinDialogActivity.class.getSimpleName();
    private static final String PACKAGE = PinDialogActivity.class.getPackage().getName();
    private static final String EXTRA_PIN_TYPE = PACKAGE + ".extras.PIN_TYPE";
    private static final String EXTRA_RETURN_TYPE = PACKAGE + ".extras.RETURN_TYPE";

    // id for a notification event
    private static final int NOTIFICATION_ID = 0x13;

    // enum for specifying type of pin
    public enum PinType {
        GENERATE, VERIFY
    }

    // Local pin type
    private PinType type;
    // Local priority type
    private KeyManagerPriority.Type returnType;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.d(TAG, "onCreate");

        final Intent intent = this.getIntent();

        if (intent == null)
            throw new IllegalArgumentException("No intent found!");

        if (!intent.hasExtra(EXTRA_PIN_TYPE) || !intent.hasExtra(EXTRA_RETURN_TYPE))
            throw new IllegalArgumentException("Extras missing!");

        this.type = (PinType) intent.getSerializableExtra(EXTRA_PIN_TYPE);
        this.returnType = (KeyManagerPriority.Type) intent.getSerializableExtra(EXTRA_RETURN_TYPE);

        this.show();
    }

    @Override
    protected void onResume() {
        super.onResume();

        NotificationManager nManager = (NotificationManager) this.getSystemService(Context.NOTIFICATION_SERVICE);
        nManager.cancel(NOTIFICATION_ID);
    }

    public void show() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setView(R.layout.dialog_password)
                .setTitle(R.string.dialog_password_title)
                .setPositiveButton(android.R.string.ok, null)
                .setNegativeButton(android.R.string.cancel, null);

        final AlertDialog dialog = builder.create();
        dialog.show();

        if (type == PinType.VERIFY) {
            dialog.findViewById(R.id.password_verify).setVisibility(View.GONE);
            TextView lbInfo = (TextView) dialog.findViewById(R.id.info);
            lbInfo.setText(R.string.dialog_password_info_unlock);
        }

        // hack: in order to prevent dialog from dismissing on button click
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(final View view) {
                TextView lbError = (TextView) dialog.findViewById(R.id.error);
                EditText txPassword = (EditText) dialog.findViewById(R.id.password);

                if (type == PinType.GENERATE) {
                    EditText txPasswordVerify = (EditText) dialog.findViewById(R.id.password_verify);

                    if (txPassword.getText().length() == 0 || txPasswordVerify.getText().length() == 0)
                        return;

                    if (!txPassword.getText().toString().equals(txPasswordVerify.getText().toString())) {
                        lbError.setText(R.string.dialog_password_error_match);
                        lbError.setVisibility(View.VISIBLE);
                        return;
                    }
                }

                Log.d(TAG, "Success: " + txPassword.getText().toString());

                PinDialogActivity.this.sendResult(txPassword.getText().toString());

                dialog.dismiss();
                PinDialogActivity.this.finish();
            }
        });

        dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(final View view) {
                Log.d(TAG, "Cancelled");
                // TODO: add to init callback?
                dialog.cancel();

                PinDialogActivity.this.finish();
            }
        });
    }

    /**
     * start key protection service.
     *
     * @param result
     */
    private void sendResult(String result) {
        Intent intent = new Intent(this, KeyProtectionService.class);
        intent.setAction(KeyProtectionService.ACTION_AUTHENTICATE);
        intent.putExtra(KeyProtectionService.EXTRA_AUTH, result);
        intent.putExtra(KeyProtectionService.EXTRA_KM_TYPE, this.returnType);
        this.startService(intent);
    }

    /**
     * Function to call activity for entering pin
     * */

    public static void showPinDialog(final Context context, PinType type, KeyManagerPriority.Type ret) {
        Intent intent = new Intent(context, PinDialogActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.putExtra(EXTRA_PIN_TYPE, type);
        intent.putExtra(EXTRA_RETURN_TYPE, ret);
        context.startActivity(intent);
    }

    /**
     * Function to manage result from pin verification
     * */
    public static void showNotification(final Context context, PinType type, KeyManagerPriority.Type ret) {
        Intent intent = new Intent(context, PinDialogActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.putExtra(EXTRA_PIN_TYPE, type);
        intent.putExtra(EXTRA_RETURN_TYPE, ret);

        PendingIntent pending = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);

        Notification n = new NotificationCompat.Builder(context)
                .setSmallIcon(R.drawable.ic_lock_outline_black_24dp)
                .setContentIntent(pending)
                .setContentTitle("Action Required!")
                .setContentText("Please authenticate to the key manager...").build();

        NotificationManager nManager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
        nManager.notify(NOTIFICATION_ID, n);
    }
}
