/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.trust;

import java.util.HashMap;

/**
 * MetaInformation class stores the meta information about an entity (HashMap)
 *
 *@author Max Kolhagen
 */
public class MetaInformation extends HashMap<String, Object> {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public static final String META_ALIASES = "aliases";
	public static final String META_LAST_SYNC = "last_sync";

	public MetaInformation(){
		super();
	}

	public MetaInformation(HashMap hashMap){
		super();
		if(!hashMap.containsKey(META_ALIASES) || !hashMap.containsKey(META_LAST_SYNC))
			return;
		this.put(META_LAST_SYNC, hashMap.get(META_LAST_SYNC));
		this.put(META_ALIASES, hashMap.get(META_ALIASES));
	}
}
