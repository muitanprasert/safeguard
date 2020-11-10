/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class ServerThread extends Thread {
	protected Socket clientSocket;

	private static final int KEY_LENGTH_AES = 128;
	private static final int MAC_LENGTH = 44;
	private static int portNumber = 2018;
	
	private DataOutputStream streamOut;
	private DataInputStream streamIn;
	private File workingDir;

	private byte[] sharedKey;
	private byte[] macKey;
	private SecretKey encryptionKey;
	private int msgNumber = 0;
	private Cipher dcipher;
	private IvParameterSpec ivPB = new IvParameterSpec("encryptionIntVec".getBytes(StandardCharsets.UTF_8));
	private byte[] saltPB = "fixedSaltForEncr".getBytes();
	
	public ServerThread(Socket clientSocket) {
		this.clientSocket = clientSocket;
	}

	public void run() {
		try {
			streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
			streamOut = new DataOutputStream(clientSocket.getOutputStream());

			streamOut.writeUTF(getCertificate());
			streamOut.flush();
			boolean finished = false;

			// get the key transfer message from the client
			finished = !parseKeyTransferMessage(streamIn.readUTF());
			System.out.println("Received encrypted shared key.");

			// hash to get a different key for MAC
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(sharedKey);
			//System.out.println(sharedKey);
			macKey = md.digest();

			workingDir = new File("users");

			// read incoming messages
			while (!finished) {
				try {
					String msg = readResponse();

					System.out.println("Received msg: " + msg);
					String response = processMessage(msg);
					sendMessage(response);
					finished = msg.equals("logout");
				} catch (Exception e) {
					// disconnect if there is an error reading the input
					System.out.println(e);
					finished = true;
				}
			}

			// clean up the connections before closing
			streamIn.close();
			streamOut.close();
			System.out.println("Client connection closed");
		} catch (Exception e) {
			// print error if the server fails to create itself
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
				String password = components[2]; // raw password
				return login(username, password);
			} catch (Exception e) {
				return "Invalid credentials";
			}
		} else if (msg.startsWith("NEWKEY")) {
			int startIndex = msg.indexOf(" ")+1;
			int firstIndex = msg.indexOf(" ", startIndex)+1;
			int secondIndex = msg.indexOf(" ", firstIndex)+1;
			try {
				String username = msg.substring(startIndex, firstIndex-1);
				String keyName = msg.substring(firstIndex, secondIndex-1);
				String key = msg.substring(secondIndex);
				//System.out.println(username + " | " + key);
				return createKey(hash(username), shorthash(keyName), key);
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
	 * @throws Exception 
	 */
	protected String login(String username, String password) throws Exception {
		// check if already exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Invalid credentials";
		}

		// load the password on the file and check if it matches the input password
		File passwordFile = new File(workingDir, username + "/pw");
		//System.out.println(passwordFile);
		Scanner passwordReader = new Scanner(passwordFile);
		String savedPassword = passwordReader.nextLine();
		passwordReader.close();
		//System.out.println(savedPassword);
		//System.out.println(password);

		// log-in if passwords match
		if (savedPassword.equals(hash(password))) {
			setEncryptionKey(password);
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
			
			BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(pwf), StandardCharsets.UTF_8));
			writer.write(password); // hashed password
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
	 * @throws Exception 
	 */
	protected String createKey(String username, String keyName, String key) throws Exception {
		System.out.println("Creating key for "+username+" (hashed)");

		// check that we are not overwriting the password
		if (keyName.equals("pw")) {
			return "Key name cannot be \"pw\", please choose a different key name";
		}
		
		// check if this username exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Cannot find your key. Message may have been corrupted. Try again or reconnect to server";
		}
		
		// create the keyName file with the given key
		File pwf = new File(f, keyName);
		BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(pwf), StandardCharsets.UTF_8));
		writer.write(encryptData(key));
		System.out.println(key);
		writer.close();
		return "Successfully created a new key";
	}

	protected String loadKey(String username, String keyName) throws Exception {
		// check if this username exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "No such key. Message may have been corrupted. Try again or reconnect to server";
		}

		// load the password on the file and check if it matches the input password
		try {
			File keyFile = new File(workingDir, username + "/" + keyName);
			Scanner keyReader = new Scanner(keyFile);
			String encryptedKey = keyReader.nextLine();
			keyReader.close();
			System.out.println("Retrieved: "+encryptedKey);
			String savedKey = decryptData(encryptedKey);
			
			// log-in if passwords match
			return "Success! The requested key is: " + savedKey;
		} catch (FileNotFoundException e) {
			return "No such file, try running \"create key \" first";
		} catch (Exception e) {
			return "A problem occurred while retrieving the key's content";
		}
	}

	protected boolean parseKeyTransferMessage(String keyTransferMessage) throws Exception {
		// whether the key transfer message is valid
		boolean valid_message = true;

		// split the message into signed and unsigned parts
		String[] unsigned_signed = keyTransferMessage.split(",");
		String unsigned = unsigned_signed[0];
		String signed = unsigned_signed[1];
		byte[] signature = decode64(signed);

		// verify the digital signature the message
		PublicKey verificationKeyA = (PublicKey) Gen.getKeyFromFile("A", "pk", "DSA");
		Signature sign = Signature.getInstance("SHA256withDSA");
		sign.initVerify(verificationKeyA);
		sign.update(decode64(unsigned));
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
		byte[] plainText = cipher.doFinal(decode64(encryptedMessage));
		String decrypted = encode64(plainText);

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
		String identity = new String(decode64(decrypted.substring(0, 8)), StandardCharsets.UTF_8);
		identity = identity.substring(0, identity.length() - 1);
		String key = decrypted.substring(8);
		System.out.println("Estalished a session with " + identity);
		System.out.println("With shared key: " + key);

		sharedKey = decode64(key);

		return valid_message;
	}

	/**
	 * Read and decrypt message
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
	 * Helper encoder from bytes to Base64 string
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
	 * @param str
	 * @return decode bytes
	 */
	private byte[] decode64(String str) {
		str = str.replace("_", "/");
		return Base64.getMimeDecoder().decode(str);
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
		md.update(str.getBytes(StandardCharsets.UTF_8));
		byte[] macKey = md.digest();
		return encode64(macKey);
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
	 * Helper function to hash MD5
	 * 
	 * @param str
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private String shorthash(String str) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(str.getBytes(StandardCharsets.UTF_8));
		byte[] macKey = md.digest();
		return encode64(macKey);
	}
	
	/**
	 * Convert a password into an encryption key
	 * @param password
	 * @return
	 * @throws Exception
	 */
	private void setEncryptionKey(String password) throws Exception {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), saltPB, 1024, 256);
        SecretKey tmp = factory.generateSecret(spec);
        dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptionKey = new SecretKeySpec(tmp.getEncoded(), "AES");
        //System.out.println("Encryption key: "+encryptionKey.getEncoded());
    }
    
	public String encryptData(String data) throws Exception {
        dcipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivPB);
        byte[] utf8EncryptedData = dcipher.doFinal(data.getBytes("UTF-8"));
        return encode64(utf8EncryptedData);
    }

    public String decryptData(String encrypted) throws Exception {
        dcipher.init(Cipher.DECRYPT_MODE, encryptionKey, ivPB);
        byte[] decryptedData = decode64(encrypted);
        byte[] utf8 = dcipher.doFinal(decryptedData);
        return new String(utf8, "UTF-8");
    }
    
	public static void main(String[] args) throws Exception {
		try {
			new Server();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
