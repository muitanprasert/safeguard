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
import java.io.FileWriter;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class Server {
	private int portNumber = 1999;
	private DataOutputStream streamOut;
	private DataInputStream streamIn;
	private static final int KEY_LENGTH_AES = 128;

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

			sendMessage(getCertificate());
			
			// key transport protocol
			
			
						
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
	
	protected String getCertificate() throws Exception {
		// generate public/private key
		Gen gen = new Gen();
		gen.generateEncrptionKey("B");
		Key pubKeyB = Gen.getKeyFromFile("B", "pk", "RSA");
		String publicB = encode64(pubKeyB.getEncoded());
		
		// sign with CA secret key
		PrivateKey signKeyCA = (PrivateKey) Gen.getKeyFromFile("CA", "sk", "DSA");
		Signature sign = Signature.getInstance("SHA256withDSA");
		sign.initSign(signKeyCA);
		sign.update(decode64(publicB));
		String signature = encode64(sign.sign());
		
		return publicB+","+signature;
	}

	/**
	 * Sends a message to the data output stream
	 * 
	 * @throws IOException
	 */
	protected void sendMessage(String msg) throws IOException {
		streamOut.writeUTF(msg);
		streamOut.flush();
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
				String username = hash(components[1]);
				String password = hash(components[2]);
				return createUser(username, password);
			} catch (Exception e) {
				return "Failed to create an account. Please try again.";
			}
		} else if (msg.startsWith("LOGIN")) {
			String[] components = msg.split(" ");
			try {
				String username = hash(components[1]);
				String password = hash(components[2]);
				return login(username, password);
			} catch (Exception e) {
				return ". Please try again.";
			}
		} else if (msg.startsWith("NEWKEY")) {
			String[] components = msg.split(" ");
			try {
				String username = hash(components[1]);
				String keyName = shorthash(components[2]);
				String key = components[3];
				return createKey(username, keyName, key);
			} catch (Exception e) {
				return "An error occurred. Please try again.";
			}
		} else if (msg.startsWith("LOADKEY")) {
			String[] components = msg.split(" ");
			try {
				String username = hash(components[1]);
				String keyName = shorthash(components[2]);
				return loadKey(username, keyName);
			} catch (Exception e) {
				return e.getMessage() + "Failed to load key. Please try again.";
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
		File f = new File("./" + username);
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
	 * Create a new user on the file system with the specified username and
	 * password
	 * 
	 * @param username
	 * @param password
	 * @return
	 * @throws IOException
	 */
	protected String createUser(String username, String password) throws IOException {
		
		// check if already exists
		File f = new File("./" + username);
		if (f.exists() && f.isDirectory()) {
			return "Username already in use. Please pick a different username.";
		}

		// create the account with the given password
		if (f.mkdir()) {
			FileOutputStream fos = new FileOutputStream("./" + username + "/pw");
			fos.write(decode64(password));
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
		System.out.println(username);
		
		// check that we are not overwriting the password
		if (keyName.equals("pw")) {
			return "Key name cannot be \"pw\", please choose a different key name";
		}

		// check if this username exists
		File f = new File("./" + username);
		if (!f.exists() || !f.isDirectory()) {
			return "No such username. Message may have been corrupted. Try again or reconnect to server";
		}

		// create the keyName file with the given key
		FileWriter fos = new FileWriter(new File(f, keyName));
		fos.write(key);
		fos.close();
		return "Successfully created a new key";

	}

	protected String loadKey(String username, String keyName) {
		// check if this username exists
		File f = new File("./" + username);
		if (!f.exists() || !f.isDirectory()) {
			return "No such username. Message may have been corrupted. Try again or reconnect to server";
		}

		// load the password on the file and check if it matches the input password
		try {
			File keyFile = new File("./" + username + "/" + keyName);
			Scanner keyReader = new Scanner(keyFile);
			String savedKey = keyReader.nextLine();
			keyReader.close();

			// log-in if passwords match
			return "Success! The requested key is: " + savedKey;
		} catch (FileNotFoundException e) {
			return "No such file, try running \"create key \" first";
		}
	}

	/**
	 * Helper encoder from bytes to Base64 string
	 * 
	 * @param bytes
	 * @return encoded string
	 */
	private String encode64(byte[] bytes) {
		Base64.Encoder encoder = Base64.getMimeEncoder();
		return encoder.encodeToString(bytes);
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
	
	/**
	 * Helper function to hash with SHA-256
	 * @param str
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private String hash(String str) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(str.getBytes());
		byte[] macKey = md.digest();
		return encode64(macKey);
	}
	
	/**
	 * Helper function to hash MD5
	 * @param str
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private String shorthash(String str) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(str.getBytes());
		byte[] macKey = md.digest();
		return encode64(macKey);
	}

	public static void main(String[] args) throws Exception {
		try {
			new Server();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
