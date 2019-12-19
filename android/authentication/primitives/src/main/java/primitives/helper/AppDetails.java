/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.helper;

import primitives.keys.Fingerprint;

import java.io.Serializable;

/**
 * AppDetails class holds details about an app. The package name is always present and indicates from which app a
 * sub key was registered from. The signature fingerprint is only present if the sub key is
 * restricted in its usage to a specific app (which has been signed with this corresponding
 * signature key).
 *
 *@author Max Kolhagen
 */
public class AppDetails implements Serializable {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    /**
     * FIELDS
     */

    // for identifying the app that registered the sub-key on the local device
    // (may not be null)
    public final String packageName;

    // for filtering which apps may use this sub-key (may be null)
    public Fingerprint signatureKeyFingerprint = null;

    /**
     * Constructor.
     *
     * @param packageName
     */
    public AppDetails(final String packageName) {
        if (packageName == null)
            throw new IllegalArgumentException("package name cannot be null!");

        this.packageName = packageName;
    }

    /**
     * Checks if a certain app is authorized to use the corresponding sub key.
     *
     * @param other
     * @return
     */
    public boolean allowsFor(AppDetails other) {
        if (other == null)
            return false;

        // check if constraint was made
        if (this.signatureKeyFingerprint == null)
            return true;

        return this.signatureKeyFingerprint.equals(other.signatureKeyFingerprint);
    }

    @Override
    public String toString() {
        return "AppDetails{" + ", packageName='" + packageName + '\'' + ", signatureKey=" + signatureKeyFingerprint
                + '}';
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        AppDetails other = (AppDetails) obj;
        if (packageName == null) {
            if (other.packageName != null)
                return false;
        } else if (!packageName.equals(other.packageName))
            return false;
        if (signatureKeyFingerprint == null) {
            if (other.signatureKeyFingerprint != null)
                return false;
        } else if (!signatureKeyFingerprint.equals(other.signatureKeyFingerprint))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((packageName == null) ? 0 : packageName.hashCode());
        result = prime * result + ((signatureKeyFingerprint == null) ? 0 : signatureKeyFingerprint.hashCode());
        return result;
    }
}
