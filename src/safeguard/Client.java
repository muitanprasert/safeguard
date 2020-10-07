/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class Client {
	private int portNumber = 1999;
	DataOutputStream streamOut;
	DataInputStream streamIn;
	Scanner console;
	
	/**
	 * Constructor handles the central control of operations
	 */
	public Client() {    
		//TODO: change to another machine's address when not running locally
		String serverAddress = "localhost";
		    
		try{
			//connect to the server
		    System.out.println("Connecting to Server at ("+portNumber+", "+serverAddress +")...");
		    Socket serverSocket = new Socket(serverAddress, portNumber);
		    System.out.println("Connected to Server");
			
		    streamOut = new DataOutputStream(serverSocket.getOutputStream());
		    streamIn = new DataInputStream(new BufferedInputStream(serverSocket.getInputStream()));
		    console = new Scanner(System.in);
			
		    //log-in/register
		    String line = "";
		    System.out.println("Would you like to register or log-in?");
		    line = console.nextLine().toLowerCase();
		    while(!line.equals("register") && !line.equals("log-in")) {
		    	System.out.println("Please choose \"register\" or \"log-in\"?");
		    	line = console.nextLine().toLowerCase();
		    }
		    
		    if(line.equals("register")) {
		    	try {
			    	register();
		    	} catch(Exception e) {
		    		System.out.println(e.getMessage());
		    		System.out.println("Registration failed. Terminating connection.");
		    		line = "logout";
		    	}
		    }
		    else {
		    	//TODO log-in
		    	//check if the account exists
		    }
		    
		    
		    //send messages to server
		    
		    while(!line.equals("logout")) {
				
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
	 * Prompt the user to enter username and password and register with the server
	 * @throws IOException
	 */
	private void register() throws IOException {
		String response = null;
		do {
			System.out.print("Username: ");
	    	String username = console.nextLine();
	    	while(username.contains(" ")) {
	    		System.out.print("Username cannot contain space. Please choose another username: ");
		    	username = console.nextLine();
	    	}
	    	System.out.print("Password: ");
	    	String password = console.nextLine();
	    	while(username.contains(" ")) {
	    		System.out.print("Password cannot contain space. Please choose another password: ");
		    	password = console.nextLine();
	    	}
	    	sendMessage("CREATE "+username+" "+password);
	    	response = streamIn.readUTF();
	    	System.out.println(response);
		} while(!response.equals("Successfully created an account."));
	}
	
	/**
	 * Sends a message to the data output stream
	 * @throws IOException 
	 */
	private void sendMessage(String msg) throws IOException {
	    streamOut.writeUTF(msg);
	    streamOut.flush();
	    System.out.println("Message sent");
	}
	
	/**
	 * Helper encoder from bytes to Base64 string
	 * @param bytes
	 * @return encoded string
	 */
	private String encode64(byte[] bytes) {
		Base64.Encoder encoder = Base64.getMimeEncoder();
		return encoder.encodeToString(bytes);
	}
	
	/**
	 * Decode Base64 string to byte[]
	 * @param str
	 * @return decode bytes
	 */
	private byte[] decode64(String str) {
		Base64.Decoder decoder = Base64.getMimeDecoder();
		return decoder.decode(str);
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
