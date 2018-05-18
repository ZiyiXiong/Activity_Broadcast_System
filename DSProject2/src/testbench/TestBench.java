/**
 * 
 */
package testbench;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import testbench.TConnection;
import testbench.TListener;
import testbench.Utilities;

/**
 * @author ziyix
 *
 */
public class TestBench {

	private static final Logger log = LogManager.getLogger();
	public static ArrayList<TConnection> connections;
	private static boolean term = false;
	private static TListener listener;
	private static JSONParser parser = new JSONParser();
	public static String remoteHostname = "localhost";
	public static int remotePort = 33000;
	public static int localPort = 34000;
	private static Scanner sc;
	protected static TestBench testbench = null;

	public static TestBench getInstance() {
		if (testbench == null) {
			testbench = new TestBench();
		}
		return testbench;
	}

	TestBench() {
		connections = new ArrayList<TConnection>();
		sc = new Scanner(System.in);
		try {
			listener = new TListener();
		} catch (IOException e1) {
			log.fatal("failed to startup a listening thread: " + e1);
			System.exit(-1);
		}
		initiateConnection();
	}

	public static void main(String[] args) {
		testbench = new TestBench();
		
		while(true) {
			int ctrlCode = sc.nextInt();
			switch (ctrlCode) {
			case 0:
				connections.get(0).writeMsg(Utilities.sendAuthenticate());
				break;
			case 1:
				connections.get(0).writeMsg(Utilities.sendlogin());
				break;
			}
		}
		
		
	}

	public void initiateConnection() {
		try {
			outgoingConnection(new Socket(remoteHostname, remotePort));
		} catch (IOException e) {
			log.error("failed to make connection to "
					+ remoteHostname + ":"
					+ remotePort + " :" + e);
			System.exit(-1);
		}
	}


	/*
	 * Processing incoming messages from the connection. Return true if the
	 * connection should close.
	 */
	public synchronized boolean process(TConnection con, String sMsg) {
		JSONObject jMsg = null;
		try {
			jMsg = (JSONObject) parser.parse(sMsg);
		} catch (ParseException p) {
			log.error("JSON parse error while parsing message");
			return true;
		}
		log.debug("received an message from "
				+ socketAddress(con.getSocket()));
		log.debug(jMsg.toString());
		return false;
	}

	/*
	 * A new incoming connection has been established, and a reference is returned
	 * to it
	 */
	public synchronized TConnection incomingConnection(Socket s)
			throws IOException {
		log.debug("incomming connection: " + socketAddress(s));
		TConnection c = new TConnection(s);
		connections.add(c);
		return c;

	}

	/*
	 * A new outgoing connection has been established, and a reference is returned
	 * to it
	 */
	public synchronized TConnection outgoingConnection(Socket s)
			throws IOException {
		log.debug("outgoing connection: " + socketAddress(s));
		TConnection c = new TConnection(s);
		connections.add(c);
		return c;
	}

	/*
	 * The connection has been closed by the other party.
	 */
	public synchronized void connectionClosed(TConnection con) {
		if (!term)
			connections.remove(con);
	}


	public static String socketAddress(Socket socket) {
		return socket.getInetAddress() + ":" + socket.getPort();
	}
}
