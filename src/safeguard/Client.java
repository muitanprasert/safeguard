/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import password.PasswordStrength;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class Client {
	private static final int KEY_LENGTH_AES = 128;
	private static final int PORT_NUMBER = 2018;
	private static final int MAC_LENGTH = 44;

	// instance variables
	private DataOutputStream streamOut;
	private DataInputStream streamIn;
	private Scanner console;
	private Socket serverSocket;

	private byte[] sharedKey;
	private byte[] macKey;

	// the username that is currently logged in
	private String session_username;

	private int msgNumber = 0;

	/**
	 * Constructor handles the central control of operations
	 * 
	 * @throws Exception
	 */
	public Client() throws Exception {

		// IMPORTANT: change to another machine's address when not running locally
		String serverAddress = "localhost"; // "pom-itb-cs2.campus.pomona.edu"; //

		try {
			// connect to the server
			System.out.println("Connecting to Server at (" + PORT_NUMBER + ", " + serverAddress + ")...");
			serverSocket = new Socket(serverAddress, PORT_NUMBER);
			System.out.println("Connected to Server");

			streamOut = new DataOutputStream(serverSocket.getOutputStream());
			streamIn = new DataInputStream(new BufferedInputStream(serverSocket.getInputStream()));
			console = new Scanner(System.in, "utf-8");

			// verify certificate: server's public key and signature
			Key pubKeyB = verifyCertificate();

			// key transport protocol
			Gen gen = new Gen();
			try {
				gen.generateSigningKey("A");

				// generate key transfer message
				streamOut.writeUTF(generateKeyTransferMessage(pubKeyB));
				streamOut.flush();

				// hash to get a different key for MAC
				MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(sharedKey);
				macKey = md.digest();
			} catch (Exception e) {
				closeSockets();
				System.out.println(e);
				return;
			}

			// log-in/register
			String line = "";
			while (!line.equals("register") && !line.equals("log-in")) {
				System.out.println("Please choose \"register\" or \"log-in\"?");
				line = console.nextLine().toLowerCase();

				if (line.equals("register")) {
					try {
						register();
						System.out.println("You can now log-in with your chosen username and password.");
						line = "";
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Registration failed. Terminating connection.");
						line = "logout";
						break;
					}
				}

				if (line.equals("log-in")) {
					try {
						if (!login()) {
							line = "";
						}
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Login failed. Terminating connection.");
						line = "logout";
						break;
					}
				}
			}

			// communicate with user and server while authenticated
			// all errors from the server should've been caught; other errors result in
			// termination
			while (!line.equals("logout")) {
				System.out.println(
						"Please choose \"create key\", \"list keys\", \"load key\", \"delete key\", \"change password\" or \"logout\"?");
				line = console.nextLine().toLowerCase();
				if (line.equals("create key")) {
					try {
						createKey();
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Creating key failed. Terminating connection.");
						line = "logout";
					}
				} else if (line.equals("list keys")) {
					try {
						listKeys();
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Listing keys failed. Terminating connection");
						line = "logout";
					}
				} else if (line.equals("load key")) {
					try {
						loadKey();
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Loading key failed. Terminating connection.");
						line = "logout";
					}
				} else if (line.equals("delete key")) {
					try {
						deleteKey();
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Deleting key failed. Terminating connection.");
						line = "logout";
					}
				} else if (line.equals("change password")) {
					try {
						changePassword();
					} catch (Exception e) {
						System.out.println(e.getMessage());
						System.out.println("Changing password failed. Terminating connection.");
						line = "logout";
					}
				}
				// TODO: work in progress; not meant to actually be used
				else if (line.equals("verify with otp")) {
					sendMessage("VERIFY");
					System.out.println("Enter the OTP sent to your email:");
					String in = console.nextLine();
					sendMessage(in);
					System.out.println(readResponse());
				}
			}

			// close all the sockets and console
			sendMessage("LOGOUT");
			System.out.println("Logging out of the server...");
			System.out.println("Logout successful");
		} catch (IOException e) {
			// print error
			System.out.println("Connection failed due to following reason");
			System.out.println(e);
		}
	}

	/*------------------------------------------
	 * CLIENT-SERVER OPERATION HELPER FUNCTIONS
	 ------------------------------------------*/

	/**
	 * Prompt the user to enter their username and password to gain access to their
	 * files on the server
	 * 
	 * @throws Exception
	 * @throws NoSuchAlgorithmException
	 */
	protected boolean login() throws Exception {
		String response = null;
		// do {
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
		response = readResponse();
		System.out.println(response);

		// on a successful login, set the session username for later key accesses
		if (response.equals("Successfully logged in")) {
			session_username = username;
			return true;
		}
		// } while (!response.equals("Successfully logged in"));
		return false;
	}

	/**
	 * Prompt the user to enter username and password and register with the server
	 * 
	 * @throws Exception
	 * @throws NoSuchAlgorithmException
	 */
	protected void register() throws NoSuchAlgorithmException, Exception {
		String response = null;
		// do {
		// prompt for a username
		System.out.print("Username: ");
		String username = console.nextLine();
		while (username.contains(" ")) { // because we use space as delimiter
			System.out.print("Username cannot contain space. Please choose another username: ");
			username = console.nextLine();
		}

		// prompt for a password
		System.out.print("Password: ");
		String password = console.nextLine();
		PasswordStrength checker = new PasswordStrength();
		boolean strong = checker.check_strength(password);
		while (!strong || password.contains(" ")) {
			if (!strong)
				System.out.print("Weak password. Please choose another password: ");
			else
				System.out.print("Password cannot contain space. Please choose another password: ");
			password = console.nextLine();
			strong = checker.check_strength(password);
		}

		// send a request to create an account
		sendMessage("REGISTER " + username + " " + password);
		response = readResponse();
		System.out.println(response);
		// } while (!response.equals("Successfully created an account."));
	}

	/**
	 * Prompt the user to enter a key name and a key, then adds this pair to the
	 * file system for this user
	 * 
	 * @throws Exception
	 * @throws NoSuchAlgorithmException
	 */
	protected void createKey() throws NoSuchAlgorithmException, Exception {
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

		// send a request to create an account
		sendMessage("NEWKEY " + session_username + " " + keyName + " " + key);
		response = readResponse();
		System.out.println(response);
	}

	protected void listKeys() throws Exception {
		String response = null;

		// send a request to create an account
		sendMessage("LISTKEYS " + session_username);
		response = readResponse();
		System.out.println(response);
	}

	/**
	 * Prompts the user for a key name, and gets the key associated with this name
	 * on the file system for this user
	 * 
	 * @throws Exception
	 * @throws NoSuchAlgorithmException
	 */
	protected void loadKey() throws NoSuchAlgorithmException, Exception {
		String response = null;

		// prompt for a key name
		System.out.print("Key name: ");
		String keyName = console.nextLine();
		while (keyName.contains(" ")) {
			System.out.print("Not a valid key name. Please enter another key name: ");
			keyName = console.nextLine();
		}

		// send a request to create an account
		sendMessage("LOADKEY " + session_username + " " + keyName);
		response = readResponse();
		System.out.println(response);
	}

	/**
	 * Prompts the user for a key name and deletes it
	 * 
	 * @throws Exception
	 * @throws NoSuchAlgorithmException
	 */
	protected void deleteKey() throws Exception {
		String response = null;

		// prompt for a key name
		System.out.print("Key name: ");
		String keyName = console.nextLine();
		while (keyName.contains(" ")) {
			System.out.print("Not a valid key name. Please enter another key name: ");
			keyName = console.nextLine();
		}

		// send a request to create an account
		sendMessage("DELETEKEY " + session_username + " " + keyName);
		response = readResponse();
		System.out.println(response);
	}

	protected void changePassword() throws Exception {
		String response = null;

		// prompt for a new password
		System.out.print("Old password: ");
		String oldPassword = console.nextLine();

		// prompt for a new password
		System.out.print("New password: ");
		String newPassword = console.nextLine();
		PasswordStrength checker = new PasswordStrength();
		boolean strong = checker.check_strength(newPassword);
		while (!strong || newPassword.contains(" ")) {
			if (!strong)
				System.out.print("Weak password. Please choose another password: ");
			else
				System.out.print("Password cannot contain space. Please choose another password: ");
			newPassword = console.nextLine();
			strong = checker.check_strength(newPassword);
		}

		// send a request to create an account
		sendMessage("CHANGEPASSWORD " + session_username + " " + newPassword + " " + oldPassword);
		response = readResponse();
		System.out.println(response);
	}

	/*------------------------------------------
	 * IO HELPER FUNCTIONS
	 ------------------------------------------*/

	/**
	 * Read and decrypt message
	 * 
	 * @return
	 * @throws Exception
	 */
	protected String readResponse() throws Exception {
		String msg = streamIn.readUTF();

		// verify that the message is correct with the MAC tag
		String tag = msg.substring(0, MAC_LENGTH);
		msg = msg.substring(MAC_LENGTH);

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(macKey, "HmacSHA256"));

		String correctTag = encode64((mac.doFinal(msg.getBytes(StandardCharsets.UTF_8))));
		if (!tag.equals(correctTag)) {
			throw new Exception("MAC tag didn't match. Closing connection...");
		}

		// decrypt the message
		IvParameterSpec iv = new IvParameterSpec("encryptionIntVec".getBytes(StandardCharsets.UTF_8));
		SecretKeySpec skeySpec = new SecretKeySpec(sharedKey, "AES");

		Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipherAES.init(Cipher.DECRYPT_MODE, skeySpec, iv);

		msg = new String(cipherAES.doFinal(decode64(msg)), StandardCharsets.UTF_8);
		msg = msg.substring(8, msg.length()); // remove the message number from the message

		return msg;
	}

	/**
	 * Sends a message to the data output stream
	 * 
	 * @throws Exception
	 */
	protected void sendMessage(String msg) throws Exception {
		// tag message number in front
		msg = pad8(msgNumber) + msg;

		// encrypt message with the shared key
		IvParameterSpec iv = new IvParameterSpec("encryptionIntVec".getBytes("UTF-8"));
		SecretKeySpec skeySpec = new SecretKeySpec(sharedKey, "AES");
		Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		cipherAES.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

		// getBytes okay because line is human-readable text
		msg = encode64(cipherAES.doFinal(msg.getBytes("UTF-8")));

		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
		String tag = encode64(mac.doFinal(msg.getBytes("UTF-8")));
		msg = tag + msg;

		// increment message number
		msgNumber++;

		// send encrypted message to the server
		streamOut.writeUTF(msg);
		streamOut.flush();
	}

	/**
	 * Helper function to close all sockets
	 * 
	 * @throws IOException
	 */
	private void closeSockets() throws IOException {
		console.close();
		streamOut.close();
		streamIn.close();
		serverSocket.close();
	}

	/*------------------------------------------
	 * CRYPTOGRAPHIC HELPER FUNCTIONs
	 ------------------------------------------*/

	/**
	 * Verify the server's certificate and return their public key if successful
	 * 
	 * @return
	 * @throws Exception
	 */
	protected Key verifyCertificate() throws Exception {
		boolean verified;

		// get certificate as a message from server
		try {
			String cert = streamIn.readUTF();
			byte[] publicB = decode64(cert.split(",")[0]);
			byte[] signedPublicB = decode64(cert.split(",")[1]);
			PublicKey verificationKeyCA = (PublicKey) Gen.getKeyFromFile("CA", "pk", "DSA");
			Signature sign = Signature.getInstance("SHA256withDSA");
			sign.initVerify(verificationKeyCA);
			sign.update(publicB);
			verified = sign.verify(signedPublicB);

			// terminate immediately if the certificate does not verify
			if (verified) {
				System.out.println("Certificate verified.");
				KeyFactory kf = KeyFactory.getInstance("RSA");
				X509EncodedKeySpec spec = new X509EncodedKeySpec(publicB);
				return kf.generatePublic(spec);
			} else
				throw new Exception();
		} catch (Exception e) {
			closeSockets();
			throw e;// new Exception("Certificate verification failed. Terminating.");
		}
	}

	protected String generateKeyTransferMessage(Key pubKeyB) throws Exception {

		// load the RSA encryption scheme
		SecureRandom random = new SecureRandom();
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher cipherRSA = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");

		// generate the symmetric Key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(KEY_LENGTH_AES); // for example
		SecretKey secretKey = keyGen.generateKey();

		// save the shared key and concatenate it with the name of the client
		sharedKey = secretKey.getEncoded(); // encryption key
		byte[] messageToEncrypt = concatBytes("Alice,".getBytes("UTF-8"), sharedKey);
		System.out.println("Shared key in Base64: " + encode64(sharedKey));

		// encode the client name + shared key with B's public key
		cipherRSA.init(Cipher.ENCRYPT_MODE, pubKeyB, random);
		String encryptedMessage = encode64(cipherRSA.doFinal(messageToEncrypt));

		// Add the server name + current time + client name + encrypted key for full
		// message
		long currentTime = System.currentTimeMillis();
		String keyTransportMessage = "Bob|" + Long.toString(currentTime) + "|" + encryptedMessage;

		// get the client's signing key
		PrivateKey signKeyA = (PrivateKey) Gen.getKeyFromFile("A", "sk", "DSA");

		// generate the signature for the message with the client's signing key
		Signature sign = Signature.getInstance("SHA256withDSA");
		sign.initSign(signKeyA);

		sign.update(decode64(keyTransportMessage));
		String signature = encode64(sign.sign());

		// return the full message plus the signature of the message
		return keyTransportMessage + "," + signature;
	}

	/**
	 * Encoder from bytes to Base64 string (avoids slash)
	 * 
	 * @param bytes
	 * @return encoded string
	 */
	private String encode64(byte[] bytes) {
		String str = Base64.getMimeEncoder().encodeToString(bytes);
		return str.replace("/", "_");
	}

	/**
	 * Decode Base64 string to byte[]
	 * 
	 * @param base64 string (possibly with _ but no /)
	 * @return decode bytes
	 */
	private byte[] decode64(String str) {
		str = str.replace("_", "/");
		return Base64.getMimeDecoder().decode(str);
	}

	/**
	 * concat bytes a and b together
	 * 
	 * @param a
	 * @param b
	 * @return
	 */
	private byte[] concatBytes(byte[] a, byte[] b) {
		byte[] result = new byte[a.length + b.length];
		System.arraycopy(a, 0, result, 0, a.length);
		System.arraycopy(b, 0, result, a.length, b.length);
		return result;
	}

	/**
	 * pads the integer n with 8 zeros
	 * 
	 * @param n
	 * @return
	 */
	private String pad8(int n) {
		String strN = Integer.toString(n);
		String padding = "00000000".substring(0, 8 - strN.length());
		return padding + strN;
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
