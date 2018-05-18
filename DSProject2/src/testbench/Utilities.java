
package testbench;

import org.json.simple.JSONObject;

public class Utilities {

    @SuppressWarnings("unchecked")
    public static String sendAuthenticate() {
        JSONObject authenticate = new JSONObject();
        authenticate.put("command", "AUTHENTICATE");
        authenticate.put("secret", "group666");
        authenticate.put("hostname", "localhost");
        authenticate.put("port", Integer.toString(TestBench.localPort));
        return authenticate.toJSONString();
    }
    
    @SuppressWarnings("unchecked")
	public static String sendlogin() {
    	JSONObject login = new JSONObject();
    	login.put("command", "LOGIN");
        login.put("username", null);
        login.put("secret", null);
        return login.toJSONString();
    }
	
}
