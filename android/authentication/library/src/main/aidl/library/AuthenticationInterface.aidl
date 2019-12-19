// AuthenticationInterface.aidl
package library;

import primitives.helper.ObjectWrapper;

// Declare any non-default types here with import statements
// https://developer.android.com/guide/components/aidl.html
// https://developer.android.com/guide/components/bound-services.html#Binder
interface AuthenticationInterface {
	/**
	 * Checking if the service is installed, available and successfully
     * initialized.
     */
    boolean isInitialized();

	/**
	 * Triggering the service to conduct the handshake protocol with
     * a given neighbor.
     */
    boolean performHandshake(in ObjectWrapper fingerprint);

	/**
	 * Indicating if a given neighbor is known or trusted and if so, to
     * what degree.
     */
    ObjectWrapper getTrustInfo(in ObjectWrapper fingerprint);

	/**
	 * Retrieving additional information about a neighbor (alias(es),
     * last encounter, etc.).
     */
    ObjectWrapper getMetaInformation(in ObjectWrapper fingerprint); // trusted introducers, aliases cert path (FPs), last encounter etc.

	/**
	 * Requesting and registering an app-specific sub key certificate.
     */
    boolean requestSubKeySignature(in byte[] publicSubKey, boolean bindToApp, in String tag);

	/**
	 * Providing associated sub keys for a given fingerprint.
     */
    ObjectWrapper getAvailableSubKeys(in ObjectWrapper fingerprint, in String tag);

	/**
	 * Providing the requested sub key for a given fingerprint and key ID.
     */
    byte[] getSubKey(in ObjectWrapper fingerprint, in ObjectWrapper keyID);
}
