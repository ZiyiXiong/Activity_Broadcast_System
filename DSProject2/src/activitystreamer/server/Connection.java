/**
 * 
 * @author modified by
 *         group666:
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

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import activitystreamer.util.Settings;

public class Connection extends Thread {
    private static final Logger log = LogManager.getLogger();
    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;
    private BufferedReader inreader;
    private PrintWriter outwriter;
    private boolean open = false;
    private boolean term = false;
    
    // indicate whether this connection belongs to a server
    private boolean isServer = false;
    
    // indicate how many lock allowed has received
    private int nRequestAllo;
    
    public int getNRequestAllo() {
        return nRequestAllo;
    }

    public void setNRequestAllo(int nRequestAllo) {
        this.nRequestAllo = nRequestAllo;
    }

    public void incrementNRequestAllo() {
        this.nRequestAllo++;
    }
    
    public boolean isServer() {
        return isServer;
    }

    public void setServer(boolean isServer) {
        this.isServer = isServer;
    }

    Connection(Socket socket) throws IOException {
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
            log.info("closing connection " + Settings.socketAddress(socket));
            try {
                term = true;
                inreader.close();
                out.close();
            } catch (IOException e) {
                // already closed?
                log.error("received exception closing the connection "
                        + Settings.socketAddress(socket) + ": " + e);
            }
        }
    }

    public void run() {
        try {
            String data;
            while (!term && (data = inreader.readLine()) != null) {
                term = Control.getInstance().process(this, data);
            }
            log.debug(
                    "connection closed to " + Settings.socketAddress(socket));
            Control.getInstance().connectionClosed(this);
            in.close();
        } catch (IOException e) {
            log.error("connection " + Settings.socketAddress(socket)
                    + " closed with exception: " + e);
            Control.getInstance().connectionClosed(this);
        } 
        open = false;
    }
    
    public Socket getSocket() {
        return socket;
    }

    public boolean isOpen() {
        return open;
    }
}
