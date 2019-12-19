/*
 * Copyright 2010 Aalto University, ComNet
 * Released under GPLv3. See LICENSE.txt for details.
 */

package report;

import applications.AuthenticationApplication;
import core.Application;
import core.ApplicationListener;
import core.DTNHost;

/**
 * Reporter for the <code>PingApplication</code>. Counts the number of pings
 * and pongs sent and received. Calculates success probabilities.
 *
 * @author teemuk
 */
public class AuthAppReporter extends Report implements ApplicationListener {

	private int nroOfSyncRequest=0, nroOfHandshake=0;
	private int nroOfHandshakeInit=0, nroOfSync=0;
	private int nroOfNon =0;

	public void gotEvent(String event, Object params, Application app,
			DTNHost host) {
		// Check that the event is sent by correct application type
		if (!(app instanceof AuthenticationApplication)) return;

		if(event.isEmpty()) return;			
		
		// Increment the counters based on the event type
		if (event.equalsIgnoreCase("Sync_Request")) {
			nroOfSyncRequest++;
		}
		if (event.equalsIgnoreCase("Handshake_Sig")) {
			nroOfHandshake++;
		}
		if (event.equalsIgnoreCase("Sync")) {
			nroOfSync++;
		}
		if (event.equalsIgnoreCase("Handshake_Init")) {
			nroOfHandshakeInit++;
		}
		
		if(event.equalsIgnoreCase("Unknown") || event.equalsIgnoreCase("nan")){
			nroOfNon++;
		}

	}


	@Override
	public void done() {
		write("Authentication stats for scenario " + getScenarioName() +
				"\nsim_time: " + format(getSimTime()));

		/*String statsText = "sync request sent/received " + this.nroOfSyncRequest +
			"\nhandshake sig sent/received: " + this.nroOfHandshake +
			"\nsync sent/received: " + this.nroOfSync +
			"\nhandshake init sent/received: " + this.nroOfHandshakeInit +
			"\nUnknown sent/received: " + this.nroOfNon
			;
*/
		//final SimulationNetworkInterface nwi = 
		//String statsText = "sync request sent " + ;
		//write(statsText);
		super.done();
	}
}
