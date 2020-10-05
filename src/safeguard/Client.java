/**
 * 
 */
package safeguard;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Scanner;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class Client {
	private int portNumber = 1999;
	
	/**
	 * 
	 */
	public Client() {    
		//TODO: change to another machine's address when not running locally
		String serverAddress = "localhost";
		    
		try{
			//connect to the server
		    System.out.println("Connecting to Server at ("+portNumber+", "+serverAddress +")...");
		    Socket serverSocket = new Socket(serverAddress, portNumber);
		    System.out.println("Connected to Server");
			
		    DataOutputStream streamOut = new DataOutputStream(serverSocket.getOutputStream());
		    Scanner console = new Scanner(System.in);
				
		    //send messages to server
		    String line = "";
		    while(!line.equals("done")) {
				try {
				    System.out.print("Type message: ");
				    line = console.nextLine();
				    streamOut.writeUTF(line);
				    streamOut.flush();
				    System.out.println("Message sent");
					
				} catch(IOException ioe) {  
				    System.out.println("Sending error: " + ioe.getMessage());
				}
		    }
			
		    //close all the sockets and console 
		    console.close();
		    streamOut.close();
		    serverSocket.close();
			
		}
		catch(IOException e) {
		    //print error
		    System.out.println("Connection failed due to following reason");
		    System.out.println(e);
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			Client client = new Client();
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	}

}
