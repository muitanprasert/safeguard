/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class Server {
	private int portNumber = 1999;
	DataOutputStream streamOut;
	DataInputStream streamIn;

	public Server() throws Exception {
		try {
			// start the server
			ServerSocket server = new ServerSocket(portNumber);
			System.out.println("Server started at port " + portNumber);

			// accept a client
			Socket clientSocket = server.accept();
			System.out.println("Client connected");
			streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
			streamOut = new DataOutputStream(clientSocket.getOutputStream());

			boolean finished = false;

			// read incoming messages
			while (!finished) {
				try {
					String msg = streamIn.readUTF();
					System.out.println("Received msg: " + msg);
					String response = processMessage(msg);
					sendMessage(response);
					finished = msg.equals("logout");
				} catch (IOException ioe) {
					// disconnect if there is an error reading the input
					finished = true;
				}
			}

			// clean up the connections before closing
			server.close();
			streamIn.close();
			streamOut.close();
			System.out.println("Server closed");
		} catch (IOException e) {
			// print error if the server fails to create itself
			System.out.println("Error in creating the server");
			System.out.println(e);
		}
	}

	/**
	 * Sends a message to the data output stream
	 * 
	 * @throws IOException
	 */
	protected void sendMessage(String msg) throws IOException {
		streamOut.writeUTF(msg);
		streamOut.flush();
		System.out.println("Message sent: " + msg);
	}

	/**
	 * Process an incoming message by detecting the type of request and calling
	 * corresponding function Messaage type: REGISTER, LOGIN, NEWKEY, LOADKEY, etc.
	 * 
	 * @param msg
	 * @return the server's response
	 */
	protected String processMessage(String msg) {
		if (msg.startsWith("REGISTER")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				String password = components[2];
				return createUser(username, password);
			} catch (Exception e) {
				return "Failed to create an account. Please try again.";
			}
		} else if (msg.startsWith("LOGIN")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				String password = components[2];
				return login(username, password);
			} catch (Exception e) {
				return ". Please try again.";
			}
		} else if (msg.startsWith("NEWKEY")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				String keyName = components[2];
				String key = components[3];
				return createKey(username, keyName, key);
			} catch (Exception e) {
				return ". Please try again.";
			}
		} else if (msg.startsWith("LOADKEY")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				String keyName = components[2];
				return loadKey(username, keyName);
			} catch (Exception e) {
				return e.getMessage() + ". Please try again.";
			}
		}
		return "Incorrect message format. Please try again.";
	}

	/**
	 * Login to an existing account with this username and password
	 * 
	 * @param username
	 * @param password
	 * @return
	 * @throws IOException
	 */
	protected String login(String username, String password) throws IOException {
		// check if already exists
		File f = new File("./" + username); // TODO: encrypt to protect usernames
		if (!f.exists() || !f.isDirectory()) {
			return "No username/password pair. Please try again.";
		}

		// load the password on the file and check if it matches the input password
		File passwordFile = new File("./" + username + "/pw");
		Scanner passwordReader = new Scanner(passwordFile);
		String savedPassword = passwordReader.nextLine();
		passwordReader.close();

		// log-in if passwords match
		if (savedPassword.equals(password)) {
			return "Successfully logged in";
		}
		throw new IOException("Login failed"); // fail due to internal file system issues
	}

	/**
	 * Create a new user on the file system with the specifiedd username and
	 * password
	 * 
	 * @param username
	 * @param password
	 * @return
	 * @throws IOException
	 */
	protected String createUser(String username, String password) throws IOException {
		// check if already exists
		File f = new File("./" + username); // TODO: encrypt to protect usernames
		if (f.exists() && f.isDirectory()) {
			return "Username already in use. Please pick a different username.";
		}

		// create the account with the given password
		if (f.mkdir()) {
			FileOutputStream fos = new FileOutputStream("./" + username + "/pw");
			fos.write(password.getBytes("utf-8")); // TODO: encrypt to protect passwords
			fos.close();
			return "Successfully created an account.";
		}
		throw new IOException(); // fail to create due to internal file systems issues
	}

	/**
	 * Create a new key with the key name on the file system
	 * 
	 * @param username
	 * @param keyName
	 * @param key
	 * @return
	 * @throws IOException
	 */
	protected String createKey(String username, String keyName, String key) throws IOException {
		// check that we are not overwritting the password
		if (keyName.equals("pw")) {
			return "Key name cannot be \"pw\", please choose a different key name";
		}

		// check if this username exists
		File f = new File("./" + username); // TODO: encrypt to protect usernames
		if (!f.exists() && !f.isDirectory()) {
			return "No such username, message may have been corrupted. Try again or reconnect to server";
		}

		// create the keyName file with the given key
		FileOutputStream fos = new FileOutputStream("./" + username + "/" + keyName);
		fos.write(key.getBytes("utf-8")); // TODO: encrypt to protect passwords
		fos.close();
		return "Successfully created a new key";

	}

	protected String loadKey(String username, String keyName) {
		// check if this username exists
		File f = new File("./" + username); // TODO: encrypt to protect usernames
		if (!f.exists() && !f.isDirectory()) {
			return "No such username, message may have been corrupted. Try again or reconnect to server";
		}

		// load the password on the file and check if it matches the input password
		try {
			File keyFile = new File("./" + username + "/" + keyName);
			Scanner keyReader = new Scanner(keyFile);
			String savedKey = keyReader.nextLine();
			keyReader.close();

			// log-in if passwords match
			return "Success! Key under name \"" + keyName + "\" is: " + savedKey;
		} catch (FileNotFoundException e) {
			return "No such file, try running \"create key \" first";
		}
	}

	/**
	 * Decode Base64 string to byte[]
	 * 
	 * @param str
	 * @return decode bytes
	 */
	private byte[] decode64(String str) {
		Base64.Decoder decoder = Base64.getMimeDecoder();
		return decoder.decode(str);
	}

	public static void main(String[] args) throws Exception {
		try {
			new Server();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
