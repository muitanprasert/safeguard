/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class Server {
	private int portNumber = 1999;

	public Server() throws Exception {
		try {
			
			//start the server
		    ServerSocket server = new ServerSocket(portNumber);
		    System.out.println("Server started at port "+portNumber);
		    
		    //accept a client
		    Socket clientSocket = server.accept();
		    System.out.println("Client connected");
		    DataInputStream streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
				
		    boolean finished = false;
				
		    //read incoming messages
		    while(!finished) {
				try {
				    String incomingMsg = streamIn.readUTF();
				    System.out.println("Received msg: " + incomingMsg);
				    
				    finished = incomingMsg.equals("done");
				}
				catch(IOException ioe) {
				    //disconnect if there is an error reading the input
				    finished = true;
				}
		    }
		    
		    //clean up the connections before closing
		    server.close();
		    streamIn.close();
		    System.out.println("Server closed");
		} 
		catch (IOException e) {
		    //print error if the server fails to create itself
		    System.out.println("Error in creating the server");
		    System.out.println(e);
		}

    }
	
    public static void main(String[] args) throws Exception {
    	try {
    		Server server = new Server();
    	} catch (Exception e) {
	    	e.printStackTrace();
	    }
    }
}
