/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class Server {
	private int portNumber = 1999;
	DataOutputStream streamOut;

	public Server() throws Exception {
		try {
			
			//start the server
		    ServerSocket server = new ServerSocket(portNumber);
		    System.out.println("Server started at port "+portNumber);
		    
		    //accept a client
		    Socket clientSocket = server.accept();
		    System.out.println("Client connected");
		    DataInputStream streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
		    streamOut = new DataOutputStream(clientSocket.getOutputStream());
				
		    boolean finished = false;
				
		    //read incoming messages
		    while(!finished) {
				try {
				    String msg = streamIn.readUTF();
				    System.out.println("Received msg: " + msg);
				    String response = processMessage(msg);
				    sendMessage(response);
				    
				    finished = msg.equals("logout");
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
	
	/**
	 * Sends a message to the data output stream
	 * @throws IOException 
	 */
	private void sendMessage(String msg) throws IOException {
	    streamOut.writeUTF(msg);
	    streamOut.flush();
	    System.out.println("Message sent: " +msg);
	}
	
	private String processMessage(String msg) {
		if(msg.startsWith("CREATE")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				String password = components[2];
				return createUser(username, password);
			} catch(Exception e) {
				return "Failed to create an account. Please try again.";
			}
		}
		return "Incorrect message format. Please try again.";
	}
	
	private String createUser(String username, String password) throws IOException {
		// check if already exists
		File f = new File("./"+username); //TODO: encrypt to protect usernames
		if (f.exists() && f.isDirectory()) {
		   return "Username already in use. Please pick a different username.";
		}
		f.mkdir();
		FileOutputStream fos = new FileOutputStream("./"+username+"/pw");
		fos.write(password.getBytes()); //TODO: encrypt to protect passwords
		fos.close();
		return "Successfully created an account.";
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
	
    public static void main(String[] args) throws Exception {
    	try {
    		Server server = new Server();
    	} catch (Exception e) {
	    	e.printStackTrace();
	    }
    }
}
