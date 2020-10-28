/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;

import password.PasswordStrength;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class Client {

	// instance variables
	private int portNumber = 1999;
	private DataOutputStream streamOut;
	private DataInputStream streamIn;
	private Scanner console;
	private Socket serverSocket;

	// the username that is currently logged in
	private String session_username;

	/**
	 * Constructor handles the central control of operations
	 * @throws Exception 
	 */
	public Client() throws Exception {
		
		// IMPORTANT: change to another machine's address when not running locally
		String serverAddress = "localhost";

		try {
			// connect to the server
			System.out.println("Connecting to Server at (" + portNumber + ", " + serverAddress + ")...");
			serverSocket = new Socket(serverAddress, portNumber);
			System.out.println("Connected to Server");

			streamOut = new DataOutputStream(serverSocket.getOutputStream());
			streamIn = new DataInputStream(new BufferedInputStream(serverSocket.getInputStream()));
			console = new Scanner(System.in, "utf-8");
			
			// verify certificate: server's public key and signature
			Key pubKeyB = verifyCertificate();
			
			// key transport protocol
			Gen gen = new Gen();
			try{
				gen.generateSigningKey("A");
			}
			catch(Exception e) {
				System.out.println(e);
			}
			

			// log-in/register
			String line = "";
			System.out.println("Would you like to register or log-in?");
			line = console.nextLine().toLowerCase();
			while (!line.equals("register") && !line.equals("log-in")) {
				System.out.println("Please choose \"register\" or \"log-in\"?");
				line = console.nextLine().toLowerCase();
			}
			
			if (line.equals("register")) {
				try {
					register();
					System.out.println("You can now log-in with your chosen username and password.");
					line = "login";
				} catch (Exception e) {
					System.out.println(e.getMessage());
					System.out.println("Registration failed. Terminating connection.");
					line = "logout";
				}
			}
			
			if (line.equals("log-in")) {
				try {
					login();
				} catch (Exception e) {
					System.out.println(e.getMessage());
					System.out.println("Login failed. Terminating connection.");
					line = "logout";
				}
			}

			// communicate with user and server while authenticated
			while (!line.equals("logout")) {
				System.out.println("Please choose \"create key\" or \"load key\" or \"logout\"?");
				line = console.nextLine();
				if (line.equals("create key")) {
					try {
						createKey();
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Creating key failed. Terminating connection.");
						line = "logout";
					}
				}
				if (line.equals("load key")) {
					try {
						loadKey();
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Creating key failed. Terminating connection.");
						line = "logout";
					}
				}
			}

			// close all the sockets and console
			System.out.println("Logging out of the server...");
			
			System.out.println("Logout successful");
		} catch (IOException e) {
			// print error
			System.out.println("Connection failed due to following reason");
			System.out.println(e);
		}
	}

	/**
	 * Prompt the user to enter their username and password to gain access to their
	 * files on the server
	 * 
	 * @throws IOException
	 */
	protected void login() throws IOException {
		String response = null;
		do {
			// prompt for a username
			System.out.print("Username: ");
			String username = console.nextLine();
			while (username.contains(" ")) {
				System.out.print("Invalid username. Re-enter username: ");
				username = console.nextLine();
			}
			// prompt for a password
			System.out.print("Password: ");
			String password = console.nextLine();
			while (username.contains(" ")) {
				System.out.print("Invalid password. Re-enter password: ");
				password = console.nextLine();
			}

			// send a request to create an account
			sendMessage("LOGIN " + username + " " + password);
			response = streamIn.readUTF();
			System.out.println(response);

			// on a successful login, set the session username for later key accesses
			if (response.equals("Successfully logged in"))
				session_username = username;
		} while (!response.equals("Successfully logged in"));
	}

	/**
	 * Prompt the user to enter username and password and register with the server
	 * 
	 * @throws IOException
	 */
	protected void register() throws IOException {
		String response = null;
		do {
			// prompt for a username
			System.out.print("Username: ");
			String username = console.nextLine();
			while(username.contains(" ")) { // because we use space as delimiter
				System.out.print("Username cannot contain space. Please choose another password: ");
				username = console.nextLine();
			}

			// prompt for a password
			System.out.print("Password: ");
			String password = console.nextLine();
			PasswordStrength checker = new PasswordStrength();
			boolean strong = checker.check_strength(password);
			while (!strong || password.contains(" ")) {
				if(!strong)
					System.out.print("Weak password. Please choose another password: ");
				else
					System.out.print("Password cannot contain space. Please choose another password: ");
				password = console.nextLine();
				strong = checker.check_strength(password);
			}

			// send a request to create an account
			sendMessage("REGISTER " + username + " " + password);
			response = streamIn.readUTF();
			System.out.println(response);
		} while (!response.equals("Successfully created an account."));
	}

	/**
	 * Prompt the user to enter a key name and a key, then adds this pair to the
	 * file system for this user
	 * 
	 * @throws IOException
	 */
	protected void createKey() throws IOException {
		String response = null;
		
		// prompt for a key name
		System.out.print("Key name: ");
		String keyName = console.nextLine();
		while (keyName.contains(" ")) {
			System.out.print("Key name cannot contain space. Please choose another key name: ");
			keyName = console.nextLine();
		}

		// prompt for a key
		System.out.print("Key: ");
		String key = console.nextLine();
		while (key.contains(" ")) {
			System.out.print("Key cannot contain space. Please choose another key: ");
			key = console.nextLine();
		}

		// send a request to create an account
		sendMessage("NEWKEY " + session_username + " " + keyName + " " + key);
		response = streamIn.readUTF();
		System.out.println(response);
	}

	/**
	 * Prompts the user for a key name, and gets the key associated with this name
	 * on the file system for this user
	 * 
	 * @throws IOException
	 */
	protected void loadKey() throws IOException {
		String response = null;
		
		// prompt for a key name
		System.out.print("Key name: ");
		String keyName = console.nextLine();
		while (keyName.contains(" ")) {
			System.out.print("Key name cannot contain space. Please choose another key name: ");
			keyName = console.nextLine();
		}

		// send a request to create an account
		sendMessage("LOADKEY " + session_username + " " + keyName);
		response = streamIn.readUTF();
		System.out.println(response);
	}
	
	/**
	 * Verify the server's certificate and return their public key if successful
	 * @return
	 * @throws Exception
	 */
	protected Key verifyCertificate() throws Exception{
		boolean verified;
		
		// get certificate as a message from server
		try {
			String cert = streamIn.readUTF();
			byte[] publicB = decode64(cert.split(",")[0]);
			byte[] signedPublicB = decode64(cert.split(",")[1]);
			PublicKey verificationKeyCA = (PublicKey) Gen.getKeyFromFile("src/CA", "pk", "DSA");
			Signature sign = Signature.getInstance("SHA256withDSA");
			sign.initVerify(verificationKeyCA);
			sign.update(publicB);
			verified = sign.verify(signedPublicB);
			
			// terminate immediately if the certificate does not verify
			if(verified) {
				System.out.println("Certificate verified.");
				KeyFactory kf = KeyFactory.getInstance("RSA");
				X509EncodedKeySpec spec = new X509EncodedKeySpec(publicB);
				return kf.generatePublic(spec);
			}
			else
				throw new Exception();
		} catch(Exception e) {
			throw new Exception("Certificate verification failed. Terminating.");
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
	 * Helper function to close all sockets
	 * @throws IOException 
	 */
	private void closeSockets() throws IOException {
		console.close();
		streamOut.close();
		streamIn.close();
		serverSocket.close();
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			new Client();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
