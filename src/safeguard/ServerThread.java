/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
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

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class ServerThread extends Thread {
	protected Socket clientSocket;

	private static final int KEY_LENGTH_AES = 128;
	private static final int MAC_LENGTH = 44;

	private int portNumber = 2018;
	private DataOutputStream streamOut;
	private DataInputStream streamIn;
	private File workingDir;

	private byte[] sharedKey;
	private byte[] savedMacKey;

	public Base64.Encoder encoder = Base64.getMimeEncoder();
	public Base64.Decoder decoder = Base64.getMimeDecoder();

	public ServerThread(Socket clientSocket) {
		this.clientSocket = clientSocket;
	}

	public void run() {
		try {
			streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
			streamOut = new DataOutputStream(clientSocket.getOutputStream());

			sendMessage(getCertificate());
			boolean finished = false;

			// get the key transfer message from the client
			finished = !parseKeyTransferMessage(streamIn.readUTF());
			System.out.println("Received encrypted shared key.");

			// hash to get a different key for MAC
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(sharedKey);
			System.out.println(sharedKey);
			savedMacKey = md.digest();

			workingDir = new File("users");

			// read incoming messages
			while (!finished) {
				try {
					String msg = streamIn.readUTF();

					// verify that the message is correct with the MAC tag
					String tag = msg.substring(0, MAC_LENGTH);
					msg = msg.substring(MAC_LENGTH);

					Mac mac = Mac.getInstance("HmacSHA256");
					mac.init(new SecretKeySpec(savedMacKey, "HmacSHA256"));

					String correctTag = encoder.encodeToString((mac.doFinal(msg.getBytes())));
					if (!tag.equals(correctTag)) {
						System.out.println("MAC tag didn't match. Closing connection...");
						break;
					}

					// decrypt the message
					IvParameterSpec iv = new IvParameterSpec("encryptionIntVec".getBytes("UTF-8"));
					SecretKeySpec skeySpec = new SecretKeySpec(sharedKey, "AES");

					Cipher cipherAES = Cipher.getInstance("AES/CBC/PKCS5PADDING");
					cipherAES.init(Cipher.DECRYPT_MODE, skeySpec, iv);

					msg = new String(cipherAES.doFinal(decoder.decode(msg)), StandardCharsets.UTF_8);
					msg = msg.substring(8, msg.length()); // remove the message number from the message

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
			streamIn.close();
			streamOut.close();
			System.out.println("Client connection closed");
		} catch (Exception e) {
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

		return publicB + "," + signature;
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
				return "Invalid credentials";
			}
		} else if (msg.startsWith("NEWKEY")) {
			String[] components = msg.split(" ");
			try {
				String username = hash(components[1]);
				System.out.println("hash1");
				String keyName = shorthash(components[2]);
				System.out.println("hash2");
				String key = components[3];
				System.out.println("comp_missing");
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
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Invalid credentials";
		}

		System.out.println(username);
		// load the password on the file and check if it matches the input password
		File passwordFile = new File(workingDir, username + "/pw");
		System.out.println(passwordFile);
		Scanner passwordReader = new Scanner(passwordFile);
		String savedPassword = passwordReader.nextLine();
		passwordReader.close();
		System.out.println(savedPassword);
		System.out.println(password);

		// log-in if passwords match
		if (savedPassword.equals(password)) {
			return "Successfully logged in";
		}
		throw new IOException("Invalid credentials");
	}

	/**
	 * Create a new user on the file system with the specified username and password
	 * 
	 * @param username
	 * @param password
	 * @return
	 * @throws IOException
	 */
	protected String createUser(String username, String password) throws IOException {

		// check if already exists
		File f = new File(workingDir, username);
		if (f.exists() && f.isDirectory()) {
			return "Username already in use. Please pick a different username.";
		}

		// create the account with the given password
		if (f.mkdir()) {
			File pwf = new File(workingDir, username + "/pw");
			BufferedWriter writer = new BufferedWriter(new FileWriter(pwf));
			writer.write(password);
			writer.close();
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
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "No such username. Message may have been corrupted. Try again or reconnect to server";
		}
		System.out.println("finished files");
		System.out.println(keyName);
		// create the keyName file with the given key
		BufferedWriter writer = new BufferedWriter(new FileWriter(new File(f, keyName)));
		System.out.println("loaded");
		writer.write(key);
		System.out.println(key);
		writer.close();
		System.out.println("writer closed");
		return "Successfully created a new key";

	}

	protected String loadKey(String username, String keyName) {
		// check if this username exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "No such username. Message may have been corrupted. Try again or reconnect to server";
		}

		// load the password on the file and check if it matches the input password
		try {
			File keyFile = new File(workingDir, username + "/" + keyName);
			Scanner keyReader = new Scanner(keyFile);
			String savedKey = keyReader.nextLine();
			keyReader.close();

			// log-in if passwords match
			return "Success! The requested key is: " + savedKey;
		} catch (FileNotFoundException e) {
			return "No such file, try running \"create key \" first";
		}
	}

	protected boolean parseKeyTransferMessage(String keyTransferMessage) throws Exception {
		// whether the key transfer message is valid
		boolean valid_message = true;

		// split the message into signed and unsigned parts
		String[] unsigned_signed = keyTransferMessage.split(",");
		String unsigned = unsigned_signed[0];
		String signed = unsigned_signed[1];
		byte[] signature = decoder.decode(signed);

		// verify the digital signature the message
		PublicKey verificationKeyA = (PublicKey) Gen.getKeyFromFile("A", "pk", "DSA");
		Signature sign = Signature.getInstance("SHA256withDSA");
		sign.initVerify(verificationKeyA);
		sign.update(decoder.decode(unsigned));
		boolean verified = sign.verify(signature);

		// split the verified unsigned parts into three components
		String encryptedMessage = unsigned.substring(unsigned.length() - 352, unsigned.length());
		int firstSplit = unsigned.indexOf('|');
		String name = unsigned.substring(0, firstSplit);
		String time = unsigned.substring(firstSplit + 1, unsigned.indexOf('|', firstSplit + 1));

		// decrypt the message
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		PrivateKey privKeyB = (PrivateKey) Gen.getKeyFromFile("B", "sk", "RSA");
		Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privKeyB);
		byte[] plainText = cipher.doFinal(decoder.decode(encryptedMessage));
		String decrypted = encoder.encodeToString(plainText);

		long currentTime = System.currentTimeMillis();

		// check the name is correct
		if (!name.equals("Bob")) {
			System.out.println("Message sent to the wrong server");
			valid_message = false;
		} else if (currentTime - Long.parseLong(time) > 120000) {
			System.out.println("Message sent too long ago");
			valid_message = false;
		} else if (!verified) {
			System.out.println("Invalid signature");
			valid_message = false;
		}
		System.out.println("Digital signature, name, and time validated.");

		// split decrypted message into identity and key
		String identity = new String(decoder.decode(decrypted.substring(0, 8)), "UTF-8");
		identity = identity.substring(0, identity.length() - 1);
		String key = decrypted.substring(8);
		System.out.println("Estalished a session with " + identity);
		System.out.println("With shared key: " + key);

		sharedKey = decoder.decode(key);

		return valid_message;
	}

	/**
	 * Helper encoder from bytes to Base64 string
	 * 
	 * @param bytes
	 * @return encoded string
	 */
	private String encode64(byte[] bytes) {
		return Base64.getUrlEncoder().encodeToString(bytes);
	}

	/**
	 * Decode Base64 string to byte[]
	 * 
	 * @param str
	 * @return decode bytes
	 */
	private byte[] decode64(String str) {
		return Base64.getUrlDecoder().decode(str);
	}

	/**
	 * Helper function to hash with SHA-256
	 * 
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
	 * 
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
