package testbench;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TConnection extends Thread {
	
	private static final Logger log = LogManager.getLogger();
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private BufferedReader inreader;
    private PrintWriter outwriter;
    private boolean open = false;
    private boolean term = false;
    
    TConnection(Socket socket) throws IOException {
        this.socket = socket;
        in = new DataInputStream(socket.getInputStream());
        out = new DataOutputStream(socket.getOutputStream());
        inreader = new BufferedReader(new InputStreamReader(in));
        outwriter = new PrintWriter(out, true);
        open = true;
        start();
    }
    
    /*
     * returns true if the message was written, otherwise false
     */
    public boolean writeMsg(String msg) {
        if (open) {
            outwriter.println(msg);
            outwriter.flush();
            return true;
        }
        return false;
    }
    
    /*
     * close this connection
     */
    public void closeCon() {
        if (open) {
            log.info("closing connection " + socketAddress(socket));
            try {
                term = true;
                inreader.close();
                out.close();
            } catch (IOException e) {
                // already closed?
                log.error("received exception closing the connection "
                        + socketAddress(socket) + ": " + e);
            }
        }
    }

    public void run() {
        try {
            String data;
            while (!term && (data = inreader.readLine()) != null) {
                term = TestBench.getInstance().process(this, data);
            }
            log.debug(
                    "connection closed to " + socketAddress(socket));
            TestBench.getInstance().connectionClosed(this);
            in.close();
        } catch (IOException e) {
            log.error("connection " + socketAddress(socket)
                    + " closed with exception: " + e);
            TestBench.getInstance().connectionClosed(this);
        } 
        open = false;
    }
    
	public static String socketAddress(Socket socket) {
		return socket.getInetAddress() + ":" + socket.getPort();
	}
    
    public Socket getSocket() {
        return socket;
    }

    public boolean isOpen() {
        return open;
    }
}
