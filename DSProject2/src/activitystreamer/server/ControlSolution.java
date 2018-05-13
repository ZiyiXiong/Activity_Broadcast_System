/**
 * This class handles all receiving and sending procedures for servers.
 * 
 * @author group666:
 *         Shujing Xiao
 *             (Login name: shujingx Email: shujingx@student.unimelb.edu.au)
 *         Ziyi Xiong
 *             (Login name: zxiong1 Email: zxiong1@student.unimelb.edu.au)
 *         Ziyi Xiong
 *             (Login name: zxiong1 Email: zxiong1@student.unimelb.edu.au)
 *         Zhengqing Zhu
 *             (Login name: zhengqingz Email: zhengqingz@student.unimelb.edu.au)
 */

package activitystreamer.server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class ControlSolution {
    
    // the secret needed for a server to connect to our network
    private static final String authenSecret = "group666";
    private static JSONParser parser = new JSONParser();
    private static final Logger log = LogManager.getLogger();
    
    /*
     * For all methods who are capable of receiving messages, they first
     * check the integrity of that message (does it contain certain fields
     * and does each field contain values), then they do corresponding
     * processing actions.
     * 
     * For all methods who are capable of sending messages, they don't
     * actually send it. They just build a corresponding JSON Object 
     * and return a String of that Object (pass the sending responsibility
     * to the caller function)
     */
    
    /**
     * send authentication to another server when start up a new server
     */
    @SuppressWarnings("unchecked")
    public static String sendAuthenticate() {
        JSONObject authenticate = new JSONObject();
        authenticate.put("command", "AUTHENTICATE");
        authenticate.put("secret", Settings.getSecret());
        return authenticate.toJSONString();
    }
    
    /**
     * when receive an authentication, handle the message
     * @return whether this connection should terminate or not
     */
    public static boolean receiveAuthenticate(Connection con, String msg) {
        log.debug("received an AUTHENTICATE from "
                + Settings.socketAddress(con.getSocket()));
        JSONObject authenticate = getJSON(con, msg);
        if (authenticate == null) {
            return true;
        }
        if (!hasValidKV("secret", authenticate, con)) {
            return true;
        }
        String response;
        if (alreadyAuthenticated(con)) {
            response = sendInvalidMessage(
                    "the server had already successfully authenticated");
            con.writeMsg(response);
            return true;
        }
        String secret = (String) authenticate.get("secret");
        if (!secret.equals(authenSecret)) {
            response = sendAuthenticationFail(
                    "the supplied secret is incorrect: " + secret);
            con.writeMsg(response);
            return true;
        }
        Control.getInstance()
                .addAuthenServer(Settings.socketAddress(con.getSocket()));
        return false;
    }
    
    /**
     * check whether a server has already authenticated or not
     * @return true if it is already authenticated
     */
    private static boolean alreadyAuthenticated(Connection con) {
        ArrayList<String> authenticatedServers = Control.getInstance()
                .getAuthenticatedServers();
        String serverSendingAddress = Settings.socketAddress(con.getSocket());
        for (String authedServ : authenticatedServers)
            if (serverSendingAddress.equals(authedServ)) {
                Control.getInstance().removeAuthenServer(serverSendingAddress);
                return true;
            }
        return false;
    }
    
    /**
     * send authentication-fail message
     * @param info indicates why fail
     */
    @SuppressWarnings("unchecked")
    private static String sendAuthenticationFail(String info) {
        JSONObject authenticationFail = new JSONObject();
        authenticationFail.put("command", "AUTHENTICATION_FAIL");
        authenticationFail.put("info", info);
        return authenticationFail.toJSONString();
    }
    
    /**
     * when receive an authentication fail message, handle it and
     * close the connection
     * @return whether this connection should terminate or not
     */
    public static boolean receiveAuthenticationFail(Connection con,
            String msg) {
        log.debug("received an AUTHENTICATION_FAIL from "
                + Settings.socketAddress(con.getSocket()));
        JSONObject authenFail = getJSON(con, msg);
        if (authenFail == null) {
            return true;
        }
        if (!hasValidKV("info", authenFail, con)) {
            return true;
        }
        log.debug("info: " + authenFail.get("info"));
        String receiveFrom = Settings.socketAddress(con.getSocket());
        if (Control.getInstance().getAuthenticatedServers()
                .contains(receiveFrom)) {
            Control.getInstance().removeAuthenServer(receiveFrom);
        }
        return true;
    }
    
    /**
     * send an invalid message when something wrong happens
     * @param info indicates what kind of violation it happens
     */
    @SuppressWarnings("unchecked")
    public static String sendInvalidMessage(String info) {
        JSONObject invalidMessage = new JSONObject();
        invalidMessage.put("command", "INVALID_MESSAGE");
        invalidMessage.put("info", info);
        return invalidMessage.toJSONString();
    }

    /**
     * when receive an invalid message, handle it and close the connection
     * @return whether this connection should terminate or not
     */
    public static boolean receiveInvalidMessage(Connection con, String msg) {
        log.debug("received an INVALID_MESSAGE from "
                + Settings.socketAddress(con.getSocket()));
        JSONObject invalidMsg = getJSON(con, msg);
        if (invalidMsg == null) {
            return true;
        }
        if (!hasValidKV("info", invalidMsg, con)) {
            return true;
        }
        log.debug("info: " + invalidMsg.get("info"));
        return true;
    }
    
    /**
     * a message indicating who am I, where I am listening, how many clients
     * I have (I am a server)
     */
    @SuppressWarnings("unchecked")
    public static String sendServerAnnounce() {
        JSONObject severAnnon = new JSONObject();
        severAnnon.put("command", "SERVER_ANNOUNCE");
        severAnnon.put("id", Control.getInstance().getServerID());
        severAnnon.put("load",
                localLoad(Control.getInstance().getConnections()));
        severAnnon.put("hostname", Settings.getLocalHostname());
        severAnnon.put("port", Settings.getLocalPort());
        return severAnnon.toJSONString();
    }

    /**
     * when receive a server announce, handle it, forward it
     * @return whether this connection should terminate or not
     */
    public static boolean receiveServerAnnounce(Connection con, String msg) {
        log.debug("received an SERVER_ANNOUNCE from "
                + Settings.socketAddress(con.getSocket()));
        if (!validServer(con)) {
            return true;
        }
        JSONObject severAnnon = getJSON(con, msg);
        if (severAnnon == null) {
            return true;
        }
        if (!hasValidKV("id", severAnnon, con)) {
            return true;
        }
        if (notContainsField("load", severAnnon, con)) {
            return true;
        }
        if (!hasValidKV("hostname", severAnnon, con)) {
            return true;
        }
        if (notContainsField("port", severAnnon, con)) {
            return true;
        }
        log.debug("received an announcement from " + severAnnon.get("id")
                + " load " + severAnnon.get("load") + " at "
                + severAnnon.get("hostname") + ":" + severAnnon.get("port"));
        updateSeverStates(severAnnon);
        broadcast(con, msg, true, true);
        return false;
    }

    /**
     * update the list where containing all information about all servers
     * which connect to the whole network
     */
    private static void updateSeverStates(JSONObject severAnnon) {
        ArrayList<Map<String, String>> interconnectedServers = Control
                .getInstance().getInterconnectedServers();
        for (Map<String, String> serverState : interconnectedServers) {
            if (serverState.get("id").equals((String) severAnnon.get("id"))) {
                Control.getInstance().removeConnectedServer(serverState);
                break;
            }
        }
        Map<String, String> serverState = new HashMap<String, String>();
        serverState.put("id", (String) severAnnon.get("id"));
        serverState.put("load", severAnnon.get("load").toString());
        serverState.put("hostname", (String) severAnnon.get("hostname"));
        serverState.put("port", severAnnon.get("port").toString());
        Control.getInstance().addConnnectedServer(serverState);
    }
    
    /**
     * when receive a login message from a client, handle it
     * @return whether this connection should terminate or not
     */
    public static boolean receiveLogin(String msg, Connection con) {
        log.debug("received a LOGIN from "
                + Settings.socketAddress(con.getSocket()));
        JSONObject login = getJSON(con, msg);
        if (login == null) {
            return true;
        }
        if (!hasValidKV("username", login, con)) {
            return true;
        }
        String username = (String) login.get("username");
        String response;
        if (username.equals("anonymous")) {
            Control.getInstance().addLoggedinAnonymous(
                    Settings.socketAddress(con.getSocket()));
            response = sendLoginSucc("anonymous");
            con.writeMsg(response);
            sendRedirect(con);
            return false;
        } else {
            if (!hasValidKV("secret", login, con)) {
                return true;
            }
            Map<String, String> registeredClients = Control.getInstance()
                    .getRegisteredClients();
            if (!registeredClients.containsKey(username)) {
                response = sendLoginFail(
                        "attempt to login with unregistered username");
                con.writeMsg(response);
                return true;
            }
            String secret = (String) login.get("secret");
            if (!secret.equals(registeredClients.get(username))) {
                response = sendLoginFail("attempt to login with wrong secret");
                con.writeMsg(response);
                return true;
            }
            Control.getInstance().addLoggedinClient(username + ":" + secret,
                    Settings.socketAddress(con.getSocket()));
            response = sendLoginSucc(username);
            con.writeMsg(response);
            sendRedirect(con);
            return false;
        }
    }
    
    /**
     * send a redirect message to a client if necessary (first check load,
     * then send)
     */
    @SuppressWarnings("unchecked")
    private static void sendRedirect(Connection con) {
        ArrayList<Connection> connections = Control.getInstance()
                .getConnections();
        int localLoad = localLoad(connections);
        ArrayList<Map<String, String>> interconnectedServers = Control
                .getInstance().getInterconnectedServers();
        for (Map<String, String> server : interconnectedServers) {
            int difference = localLoad - Integer.parseInt(server.get("load"));
            if (difference >= 2) {
                JSONObject redirInfo = new JSONObject();
                redirInfo.put("command", "REDIRECT");
                redirInfo.put("hostname", server.get("hostname"));
                redirInfo.put("port", server.get("port"));
                con.writeMsg(redirInfo.toJSONString());
                return;
            }
        }
    }
    
    /**
     * send a login fail message to a client
     * @param info indicate why login fail
     */
    @SuppressWarnings("unchecked")
    private static String sendLoginFail(String info) {
        JSONObject loginFail = new JSONObject();
        loginFail.put("command", "LOGIN_FAILED");
        loginFail.put("info", info);
        return loginFail.toJSONString();
    }
    
    /**
     * send a login success message to a client
     */
    @SuppressWarnings("unchecked")
    private static String sendLoginSucc(String username) {
        JSONObject loginSucc = new JSONObject();
        loginSucc.put("command", "LOGIN_SUCCESS");
        loginSucc.put("info", "logged in as user " + username);
        return loginSucc.toJSONString();
    }
    
    /**
     * when receive a logout message, close the connection
     * @return whether this connection should terminate or not
     */
    public static boolean receiveLogout(Connection con) {
        log.debug("received a LOGOUT from "
                + Settings.socketAddress(con.getSocket()));
        Map<String, String> loggedinClients = Control.getInstance()
                .getLoggedinClients();
        String clientAddr = Settings.socketAddress(con.getSocket());
        for (String key : loggedinClients.keySet()) {
            if (clientAddr.equals(loggedinClients.get(key))) {
                Control.getInstance().removeLoggedinClient(key);
                break;
            }
        }
        if (Control.getInstance().getLoggedinAnonymous()
                .contains(clientAddr)) {
            Control.getInstance().removeLoggedinAnonymous(clientAddr);
        }
        return true;
    }

    /**
     * when receive a register message, handle it and broadcast a lock request
     * message within servers
     * 
     *  assumption: there is no such case that two clients are registering with the
     *  same username to two different servers at the same time
     */
    public static boolean receiveRegister(String msg, Connection con) {
        log.debug("received a REGISTER from "
                + Settings.socketAddress(con.getSocket()));
        JSONObject register = getJSON(con, msg);
        if (register == null) {
            return true;
        }
        if (!hasValidKV("username", register, con)) {
            return true;
        }
        if (!hasValidKV("secret", register, con)) {
            return true;
        }
        String response;
        String username = (String) register.get("username");
        String secret = (String) register.get("secret");
        Map<String, String> registeredClients = Control.getInstance()
                .getRegisteredClients();
        if (registeredClients.containsKey(username)) {
            response = sendRegisterFail(username);
            con.writeMsg(response);
            return true;
        }
        if (Control.getInstance().getInterconnectedServers().size() == 0) {
            Control.getInstance().addRegisteredClient(username, secret);
            response = sendRegisterSucc(username);
            con.writeMsg(response);
            return false;
        }
        con.setNRequestAllo(0);
        Control.getInstance().addRegisteringClient(username, con);
        String lockReq = sendLockRequest(username, secret);
        broadcast(con, lockReq, true, false);
        return false;
    }
    
    /**
     * send a register fail message to a client
     */
    @SuppressWarnings("unchecked")
    public static String sendRegisterFail(String username) {
        JSONObject registerFail = new JSONObject();
        registerFail.put("command", "REGISTER_FAILED");
        registerFail.put("info",
                username + " is already registered with the system");
        return registerFail.toJSONString();
    }
    
    /**
     * send a register success message to a client
     */
    @SuppressWarnings("unchecked")
    public static String sendRegisterSucc(String username) {
        JSONObject registerSucc = new JSONObject();
        registerSucc.put("command", "REGISTER_SUCCESS");
        registerSucc.put("info", "register success for " + username);
        return registerSucc.toJSONString();
    }
    
    /**
     * send a lock request message to indicate a user want to register with
     * given username and secret
     */
    @SuppressWarnings("unchecked")
    private static String sendLockRequest(String username, String secret) {
        JSONObject lockReq = new JSONObject();
        lockReq.put("command", "LOCK_REQUEST");
        lockReq.put("username", username);
        lockReq.put("secret", secret);
        return lockReq.toJSONString();
    }
    
    /**
     * when receive a lock request message, handle it (first check its local
     * storage, then broadcast corresponding message within servers)
     * @return whether this connection should terminate or not
     */
    public static boolean receiveLockRequest(String msg, Connection con) {
        log.debug("received a LOCK_REQUEST from "
                + Settings.socketAddress(con.getSocket()));
        if (!validServer(con)) {
            return true;
        }
        JSONObject lockReq = getJSON(con, msg);
        if (lockReq == null) {
            return true;
        }
        if (!hasValidKV("username", lockReq, con)) {
            return true;
        }
        if (!hasValidKV("secret", lockReq, con)) {
            return true;
        }
        broadcast(con, msg, true, true);
        String response;
        String username = (String) lockReq.get("username");
        String secret = (String) lockReq.get("secret");
        Map<String, String> registeredClients = Control.getInstance()
                .getRegisteredClients();
        if (registeredClients.containsKey(username)
                && !secret.equals(registeredClients.get(username))) {
            Control.getInstance().removeRegisteredClient(username);
            response = sendLockDenied(username, secret);
            broadcast(con, response, true, false);
            return true;
        }
        if (!registeredClients.containsKey(username)) {
            Control.getInstance().addRegisteredClient(username, secret);
        }
        response = sendLockAllowed(username, secret);
        broadcast(con, response, true, false);
        return false;
    }
    
    @SuppressWarnings("unchecked")
    private static String sendLockDenied(String username, String secret) {
        JSONObject lockDen = new JSONObject();
        lockDen.put("command", "LOCK_DENIED");
        lockDen.put("username", username);
        lockDen.put("secret", secret);
        return lockDen.toJSONString();
    }
    
    /**
     * when receive a lock denied, the server will check whether it is himself 
     * who receive the register message initially, if it is, then send a
     * register fail message to that client
     * 
     * @return whether this connection should terminate or not
     */
    public static boolean receiveLockDenied(String msg, Connection con) {
        log.debug("received a LOCK_DENIED from "
                + Settings.socketAddress(con.getSocket()));
        if (!validServer(con)) {
            return true;
        }
        JSONObject lockDen = getJSON(con, msg);
        if (lockDen == null) {
            return true;
        }
        if (!hasValidKV("username", lockDen, con)) {
            return true;
        }
        if (!hasValidKV("secret", lockDen, con)) {
            return true;
        }
        String username = (String) lockDen.get("username");
        String secret = (String) lockDen.get("secret");
        Map<String, String> registeredClients = Control.getInstance()
                .getRegisteredClients();
        if (registeredClients.containsKey(username)
                && secret.equals(registeredClients.get(username))) {
            Control.getInstance().removeRegisteredClient(username);
        }
        broadcast(con, msg, true, true);
        Map<String, Connection> registeringClients = Control.getInstance()
                .getRegisteringClients();
        if (registeringClients.containsKey(username)) {
            Connection registeringCon = registeringClients.get(username);
            String response = sendRegisterFail(username);
            registeringCon.writeMsg(response);
            Control.getInstance().removeRegisteringClient(username);
        }
        return false;
    }
    
    @SuppressWarnings("unchecked")
    private static String sendLockAllowed(String username, String secret) {
        JSONObject lockAllo = new JSONObject();
        lockAllo.put("command", "LOCK_ALLOWED");
        lockAllo.put("username", username);
        lockAllo.put("secret", secret);
        return lockAllo.toJSONString();
    }
    
    /**
     * when receive a lock allowed, the server will check whether it is himself 
     * who receive the register message initially, if it is, then increment the
     * number of lock-allowed received. If the number of lock-allowd message
     * received matches the number of servers in the whole network, it will
     * send a register success to the client 
     * @return whether this connection should terminate or not
     */
    public static boolean receiveLockAllowed(String msg, Connection con) {
        log.debug("received a LOCK_ALLOWED from "
                + Settings.socketAddress(con.getSocket()));
        if (!validServer(con)) {
            return true;
        }
        JSONObject lockAllo = getJSON(con, msg);
        if (lockAllo == null) {
            return true;
        }
        if (!hasValidKV("username", lockAllo, con)) {
            return true;
        }
        if (!hasValidKV("secret", lockAllo, con)) {
            return true;
        }
        broadcast(con, msg, true, true);
        String username = (String) lockAllo.get("username");
        String secret = (String) lockAllo.get("secret");
        Map<String, Connection> registeringClients = Control.getInstance()
                .getRegisteringClients();
        if (registeringClients.containsKey(username)) {
            Connection registeringCon = registeringClients.get(username);
            registeringCon.incrementNRequestAllo();
            int nConnectedServers = Control.getInstance()
                    .getInterconnectedServers().size();
            if (registeringCon.getNRequestAllo() == nConnectedServers) {
                String response = sendRegisterSucc(username);
                registeringCon.writeMsg(response);
                Control.getInstance().removeRegisteringClient(username);
                Control.getInstance().addRegisteredClient(username, secret);
            }
        }
        return false;
    }

    /**
     * when receive an activity message, process it (add a new field in the 
     * activity JSON) and then broadcast it within the whole network
     * @return whether this connection should terminate or not
     */
    public static boolean receiveActivityMessage(Connection con, String msg) {
        log.debug("received an ACTIVITY_MESSAGE from "
                + Settings.socketAddress(con.getSocket()));
        JSONObject actMsg = getJSON(con, msg);
        if (actMsg == null) {
            return true;
        }
        if (!hasValidKV("username", actMsg, con)) {
            return true;
        }
        String username = (String) actMsg.get("username");
        if (!username.equals("anonymous")) {
            if (!hasValidKV("secret", actMsg, con)) {
                return true;
            }
        }
        if (notContainsField("activity", actMsg, con)) {
            return true;
        }
        String response;
        JSONObject activity = (JSONObject) actMsg.get("activity");
        if (activity == null) {
            response = sendInvalidMessage(
                    "the received message did not contain the activity value");
            con.writeMsg(response);
            return true;
        }
        if (!validClient(username, actMsg, con)) {
            return true;
        }
        JSONObject processedAct = processActivity(activity, username);
        String actBroadcast = sendActivityBroadcast(processedAct);
        broadcast(con, actBroadcast, false, false);
        return false;
    }
    
    @SuppressWarnings("unchecked")
    private static String sendActivityBroadcast(JSONObject processedAct) {
        JSONObject actBroadcast = new JSONObject();
        actBroadcast.put("command", "ACTIVITY_BROADCAST");
        actBroadcast.put("activity", processedAct);
        return actBroadcast.toJSONString();
    }
    
    /**
     * when receive an activity broadcast, forward it
     * @return whether this connection should terminate or not
     */
    public static boolean receiveActivityBroadcast(Connection con,
            String msg) {
        log.debug("received an ACTIVITY_BROADCAST from "
                + Settings.socketAddress(con.getSocket()));
        if (!validServer(con)) {
            return true;
        }
        JSONObject actBroadCast = getJSON(con, msg);
        if (actBroadCast == null) {
            return true;
        }
        if (notContainsField("activity", actBroadCast, con)) {
            return true;
        }
        JSONObject activity = (JSONObject) actBroadCast.get("activity");
        if (activity == null) {
            String response = sendInvalidMessage(
                    "the received message did not contain the activity value");
            con.writeMsg(response);
            return true;
        }
        broadcast(con, msg, false, true);
        return false;
    }

    /**
     * process the activity message
     * @param activity which to be processed
     * @param username which to be added into activity message
     * @return processed activity message
     */
    @SuppressWarnings("unchecked")
    private static JSONObject processActivity(JSONObject activity,
            String username) {
        activity.put("authenticated_user", username);
        return activity;
    }

    /**
     * 
     * @return whether it is a valid user (has logged in)
     */
    private static boolean validClient(String username, JSONObject actMsg,
            Connection con) {
        String clientSockAddr = Settings.socketAddress(con.getSocket());
        String response;
        if (username.equals("anonymous")) {
            if (!Control.getInstance().getLoggedinAnonymous()
                    .contains(clientSockAddr)) {
                response = sendAuthenticationFail(
                        "sending ACTIVITY_MESSAGE without logging in first");
                con.writeMsg(response);
                return false;
            }
        } else {
            String secret = (String) actMsg.get("secret");
            String identifier = username + ":" + secret;
            Map<String, String> loggedinClients = Control.getInstance()
                    .getLoggedinClients();
            if (!loggedinClients.containsKey(identifier) || !loggedinClients
                    .get(identifier).equals(clientSockAddr)) {
                response = sendAuthenticationFail(
                        "sending ACTIVITY_MESSAGE without logging in first"
                                + " or the supplied secret is incorrect: "
                                + secret);
                con.writeMsg(response);
                return false;
            }
        }
        return true;
    }

    /**
     * 
     * @return whether it is a valid server (has been authenticated)
     */
    private static boolean validServer(Connection con) {
        String receiveFrom = Settings.socketAddress(con.getSocket());
        if (!Control.getInstance().getAuthenticatedServers()
                .contains(receiveFrom)) {
            String response = sendInvalidMessage(
                    "need to be authenticated first");
            con.writeMsg(response);
            return false;
        }
        return true;
    }

    public static boolean hasSecret() {
        if (Settings.getSecret() == null) {
            return false;
        }
        log.info("using given secret: " + Settings.getSecret());
        return true;
    }
    
    /**
     * 
     * @param withinServers whether broadcast within servers only
     * @param forwardMsg whether needs to send to the sender
     */
    private static void broadcast(Connection con, String msg,
            boolean withinServers, boolean forwardMsg) {
        ArrayList<Connection> connections = Control.getInstance()
                .getConnections();
        String receivedFrom = Settings.socketAddress(con.getSocket());
        if (withinServers) {
            broadcastWithinServers(con, msg, forwardMsg, connections,
                    receivedFrom);
        } else {
            broadcastToAll(msg, forwardMsg, connections, receivedFrom);
        }
    }
    
    /**
     * broadcast to all nodes (including clients) within network
     * @param forwardMsg whether needs to send to the sender
     */
    private static void broadcastToAll(String msg, boolean forwardMsg,
            ArrayList<Connection> connections, String receivedFrom) {
        if (forwardMsg) {
            for (Connection c : connections) {
                String socAddr = Settings.socketAddress(c.getSocket());
                if (!socAddr.equals(receivedFrom))
                    c.writeMsg(msg);
            }
        } else {
            for (Connection c : connections) {
                c.writeMsg(msg);
            }
        }
    }

    /**
     * broadcast just within servers
     * @param forwardMsg whether needs to send to the sender
     */
    private static void broadcastWithinServers(Connection con, String msg,
            boolean forwardMsg, ArrayList<Connection> connections,
            String receivedFrom) {
        if (forwardMsg) {
            for (Connection c : connections) {
                String socAddr = Settings.socketAddress(c.getSocket());
                if (c.isServer() && (!socAddr.equals(receivedFrom)))
                    c.writeMsg(msg);
            }
        } else {
            for (Connection c : connections) {
                if (c.isServer())
                    c.writeMsg(msg);
            }
        }
    }

    private static boolean hasValidKV(String field, JSONObject jMsg,
            Connection con) {
        if (notContainsField(field, jMsg, con)) {
            return false;
        }
        String value = (String) jMsg.get(field);
        if (notContainsValue(value, field, con)) {
            return false;
        }
        return true;
    }

    private static boolean notContainsField(String field, JSONObject jMsg,
            Connection con) {
        if (!jMsg.containsKey(field)) {
            String response = sendInvalidMessage(
                    "the received message did not contain the " + field
                            + " field");
            con.writeMsg(response);
            return true;
        }
        return false;
    }

    private static boolean notContainsValue(String value, String field,
            Connection con) {
        if (value == null) {
            String response = sendInvalidMessage(
                    "the received message did not contain the " + field
                            + " value");
            con.writeMsg(response);
            return true;
        }
        return false;
    }
    
    /**
     * calculate the local load (how many clients connecting to it)
     */
    private static int localLoad(ArrayList<Connection> connections) {
        int load = 0;
        for (Connection connect : connections) {
            if (!connect.isServer()) {
                load++;
            }
        }
        return load;
    }

    public static JSONObject getJSON(Connection con, String sMsg) {
        try {
            JSONObject jMsg = (JSONObject) parser.parse(sMsg);
            return jMsg;
        } catch (ParseException p) {
            String response = sendInvalidMessage(
                    "JSON parse error while parsing message");
            con.writeMsg(response);
            return null;
        }
    }

    public static String getCommandName(Connection con, String sMsg) {
        String sCmd = "";
        JSONObject jMsg = getJSON(con, sMsg);
        if (jMsg == null) {
            return sCmd;
        }
        if (jMsg.containsKey("command")) {
            sCmd = (String) jMsg.get("command");
        } else {
            String response = sendInvalidMessage(
                    "the received message did not contain the command field");
            con.writeMsg(response);
        }
        return sCmd;
    }
}
