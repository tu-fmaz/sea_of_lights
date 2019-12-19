/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package keyverifier.views;

import android.content.Context;
import android.graphics.Color;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.widget.LinearLayout;
import android.widget.TextView;

import keyverifier.R;
import primitives.keys.Fingerprint;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * FingerprintView class displays the color-coded fingerprint.
 *
 *@author Max Kolhagen
 */
public class FingerprintView extends LinearLayout {
    private static final String ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android";

    /*
     * Components
     */
    private final TextView txTitle;
    private final TextView txFingerprint;

    /*
     * Fields
     */
    private Fingerprint fingerprint = null;

    /**
     * Constructor.
     *
     * @param context
     * @param attributes
     */
    public FingerprintView(final Context context, final AttributeSet attributes) {
        super(context, attributes);

        // inflate layout
        LayoutInflater inflater = LayoutInflater.from(context);
        inflater.inflate(R.layout.view_fingerprint, this);

        this.txTitle = (TextView) this.findViewById(R.id.text_title);
        this.txFingerprint = (TextView) this.findViewById(R.id.text_fingerprint);

        // set title of the component
        this.setTitle(attributes.getAttributeValue(ANDROID_NAMESPACE, "title"));
    }

    public void setTitle(String title) {
        this.txTitle.setText(title);
        this.invalidate();
        this.requestLayout();
    }

    public void setPublicKey(Fingerprint fingerprint) throws Exception {
        this.fingerprint = fingerprint;

        this.txFingerprint.setText(this.colorizeFingerprint());
        this.invalidate();
        this.requestLayout();
    }

    /**
     * Colorizes the given fingerprint.
     * <p/>
     * Source: https://github.com/open-keychain/open-keychain/blob/43e795695903eb600798a22c21e4bd07484d09c5/OpenKeychain/src/main/java/org/sufficientlysecure/keychain/ui/util/KeyFormattingUtils.java
     *
     * @return
     * @throws Exception
     */
    public SpannableStringBuilder colorizeFingerprint() throws Exception {
        String fingerprint = this.fingerprint.toString();

        // split by 4 characters
        //fingerprint = fingerprint.replaceAll("(.{16})(?!$)", "$1\n");
        fingerprint = fingerprint.replaceAll("(.{4})(?!$)", "$1 ");

        // add line breaks to have a consistent "image" that can be recognized
        char[] chars = fingerprint.toCharArray();
        for (int i = 19; i < chars.length; i += 20) {
            chars[i] = '\n';
        }
        //chars[24] = '\n';
        fingerprint = String.valueOf(chars);

        SpannableStringBuilder sb = new SpannableStringBuilder(fingerprint);
        try {
            // for each 4 characters of the fingerprint + 1 space
            for (int i = 0; i < fingerprint.length(); i += 5) {
                int spanEnd = Math.min(i + 4, fingerprint.length());
                String fourChars = fingerprint.substring(i, spanEnd);

                int raw = Integer.parseInt(fourChars, 16);
                byte[] bytes = {(byte) ((raw >> 8) & 0xff - 128), (byte) (raw & 0xff - 128)};
                int[] color = getRgbForData(bytes);
                int r = color[0];
                int g = color[1];
                int b = color[2];

                // we cannot change black by multiplication, so adjust it to an almost-black grey,
                // which will then be brightened to the minimal brightness level
                if (r == 0 && g == 0 && b == 0) {
                    r = 1;
                    g = 1;
                    b = 1;
                }

                // Convert rgb to brightness
                double brightness = 0.2126 * r + 0.7152 * g + 0.0722 * b;

                // If a color is too dark to be seen on black,
                // then brighten it up to a minimal brightness.
                if (brightness < 80) {
                    double factor = 80.0 / brightness;
                    r = Math.min(255, (int) (r * factor));
                    g = Math.min(255, (int) (g * factor));
                    b = Math.min(255, (int) (b * factor));

                    // If it is too light, then darken it to a respective maximal brightness.
                } else if (brightness > 180) {
                    double factor = 180.0 / brightness;
                    r = (int) (r * factor);
                    g = (int) (g * factor);
                    b = (int) (b * factor);
                }

                // Create a foreground color with the 3 digest integers as RGB
                // and then converting that int to hex to use as a color
                sb.setSpan(new ForegroundColorSpan(Color.rgb(r, g, b)),
                        i, spanEnd, Spannable.SPAN_INCLUSIVE_INCLUSIVE);
            }
        } catch (Exception e) {
            Log.e("Constants.TAG", "Colorization failed", e);
            // if anything goes wrong, then just display the fingerprint without colour,
            // instead of partially correct colour or wrong colours
            return new SpannableStringBuilder(fingerprint);
        }

        return sb;
    }

    /**
     * Converts the given bytes to a unique RGB color using SHA1 algorithm
     *
     * @return an integer array containing 3 numeric color representations (Red, Green, Black)
     * @throws NoSuchAlgorithmException
     * @throws DigestException
     */
    private static int[] getRgbForData(byte[] bytes) throws NoSuchAlgorithmException, DigestException {
        MessageDigest md = MessageDigest.getInstance("SHA1");

        md.update(bytes);
        byte[] digest = md.digest();

        return new int[]{((int) digest[0] + 256) % 256,
                ((int) digest[1] + 256) % 256,
                ((int) digest[2] + 256) % 256};
    }
}
