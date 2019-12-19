package auth_encryption.core;

import java.io.Serializable;

import applications.AuthenticationApplication;
import auth_encryption.simulator.SimulationUtils;
import core.DTNHost;
import core.Message;

/**
 * MessageAuthentication class generates the message for the authentication process
 * */
public abstract class MessageAuthentication extends Message implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public static final int TYPE_ALL = 0xFF;
    public static final int TYPE_UNKNOWN = 0x00;

    private int type = MessageAuthentication.TYPE_UNKNOWN;
    
    /**
     * Static variables for the initialization of a message in ONE 
     * */
    private static DTNHost staticFrom = null;
    //private static DTNHost staticTo = null;
    private static String staticId = "";
    private static int staticSize = 0;
    private static String staticSubtype = "";
    
    protected MessageAuthentication(int type, DTNHost to) {
    	super(staticFrom, to, staticId, staticSize);
    	this.type = type;
    }

    /**
     * Static function to initialize a message in ONE 
     * */
    public static void initialization(DTNHost from, //DTNHost to, 
			String id, int size){
    	staticFrom = from;
    	//staticTo = to;
    	staticSize = size;
    	staticId = id;
    }
    
    /**
     * return the type of the message to filter on the app-layer 
     * (authentication) 
     * */
	public int getType() {
        return this.type;
    }

	/**
	 * 
	 * */
	public void setSizeSerializable(DTNHost to){
		//Add the property to the message to be filtered on the app-layer
		this.addProperty("type", "authentication");
		
		this.addProperty("subtype", this.subTypeToString());
		
		staticSubtype = this.subTypeToString();
		if(to!=null){
			//staticTo = to;
			this.setTo(to);
		}
		this.setAppID(AuthenticationApplication.APP_ID);
		//Set the size of a message before it is created
        this.setSize((int)SimulationUtils.getNetworkObjectSize(this));
        //Change the message id for the auth msg
        this.setId(this.getId() + this.subTypeToString());
        //after the set all the init configuration, the message is created
        this.getFrom().createNewMessage(this);
    }
	
	public static String getSubtype(){
		return staticSubtype;
	}
	
	/**
	 * return the type of the authentication msg
	 * */	
	public String subTypeToString(){
		String result = "";
		switch(this.type){
			case SyncRequestMessage.TYPE_SYNC_REQUEST:
				result = "Sync_Request";
				break;
			case HandshakeSignatureMessage.TYPE_HANDSHAKE_SIGNATURE:
				result = "Handshake_Sig";
				break;
			case SyncMessage.TYPE_SYNC:
				result = "Sync";
				break;
			case HandshakeInitializeMessage.TYPE_HANDSHAKE_INIT:
				result = "Handshake_Init";
				break;
			case MessageAuthentication.TYPE_UNKNOWN:
				result = "Unknown";
				break;
			default:
				result ="nan";
				break;
		}
		return result;
	}
}
