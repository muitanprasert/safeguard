/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.KeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 * @author Mui Tanprasert & Alex Franklin
 *
 */
public class ServerThread extends Thread {
	protected Socket clientSocket;

	private static final int KEY_LENGTH_AES = 128;
	private static final int MAC_LENGTH = 44;
	private static final int OTP_LIMIT = 3; // minutes
	private static final int HASH_ITERATIONS = 100000;

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
	private String ip;
	private String lastLogin = "";

	public ServerThread() {
		this.clientSocket = clientSocket;
	}

	public void setSocket(Socket clientSocket) {
		this.clientSocket = clientSocket;
		this.ip = clientSocket.getRemoteSocketAddress().toString().split(":")[0];
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

			// hash to get a different key for MAC
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(sharedKey);
			// System.out.println(sharedKey);
			macKey = md.digest();

			workingDir = new File("users");

			// read incoming messages
			while (!finished) {
				try {
					String msg = readResponse();
					if (msg.equals("LOGOUT"))
						finished = true;
					else {
						String response = processMessage(msg);
						sendMessage(response);
					}
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

	/*------------------------------------------
	 * SERVER-CLIENT OPERATION HELPER FUNCTIONs
	 ------------------------------------------*/

	/**
	 * Process an incoming message by detecting the type of request and calling
	 * corresponding function Message type: REGISTER, LOGIN, NEWKEY, LOADKEY, etc.
	 * 
	 * @param msg
	 * @return the server's response
	 */
	protected String processMessage(String msg) {
		if (msg.startsWith("REGISTER")) {
			String[] components = msg.split(" ");
			try {
				String username = hash(components[1]);
				String password = components[2]; // raw password
				String email = hash(components[3]);
				return createUser(username, password, email);
			} catch (Exception e) {
				return "Failed to create an account. Please try again.";
			}
		} else if (msg.startsWith("LOGIN")) {
			String[] components = msg.split(" ");
			try {
				String username = hash(components[1]);
				String password = components[2]; // raw password
				String response = login(username, password);
				if(response.equals("Successfully logged in"))
					response = secondFactor(username);
				return response;
			} catch (Exception e) {
				return "An error occurred. Please try again.";
			}
		} else if (msg.startsWith("NEWKEY")) {
			int startIndex = msg.indexOf(" ") + 1;
			int firstIndex = msg.indexOf(" ", startIndex) + 1;
			int secondIndex = msg.indexOf(" ", firstIndex) + 1;
			try {
				String username = msg.substring(startIndex, firstIndex - 1);
				String keyName = msg.substring(firstIndex, secondIndex - 1);
				String key = msg.substring(secondIndex);
				// System.out.println(username + " | " + key);
				return createKey(hash(username), keyName, key);
			} catch (Exception e) {
				return "An error occurred. Please try again.";
			}
		} else if (msg.startsWith("LISTKEYS")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				return listKeys(hash(username));
			} catch (Exception e) {
				return e.getMessage() + "Failed to load key. Please try again.";
			}
		} else if (msg.startsWith("LOADKEY")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				String keyName = components[2];
				return loadKey(hash(username), keyName);
			} catch (Exception e) {
				return e.getMessage() + "Failed to load key. Please try again.";
			}
		} else if (msg.startsWith("DELETEKEY")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				String keyName = components[2];
				return deleteKey(hash(username), keyName);
			} catch (Exception e) {
				return "An error occurred during hashing. Please try again.";
			}
		} else if (msg.startsWith("CHANGEPASSWORD")) {
			String[] components = msg.split(" ");
			try {
				String username = components[1];
				String newPassword = components[2];
				String oldPassword = components[3];
				return changePassword(hash(username), newPassword, oldPassword);
			} catch (Exception e) {
				return "An error occurred during hashing. Please try again.";
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

		// check if exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Invalid username";
		}

		// load the password on the file and check if it matches the input password
		File passwordFile = new File(workingDir, username + "/pw");
		Scanner passwordReader = new Scanner(passwordFile);
		String savedSalt = passwordReader.nextLine();
		String savedPassword = passwordReader.nextLine();
		passwordReader.close();

		String inputPassword = hash(savedSalt + password);

		for (int i = 0; i < HASH_ITERATIONS; i++) {
			inputPassword = hash(inputPassword);
		}

		// log-in if passwords match
		if (savedPassword.equals(inputPassword)) {
			setEncryptionKey(inputPassword);
			return "Successfully logged in";
		}
		return "Invalid credentials";
	}

	/**
	 * Create a new user on the file system with the specified username and password
	 * 
	 * @param username
	 * @param password
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	protected String createUser(String username, String password, String email)
			throws IOException, NoSuchAlgorithmException {

		// check if already exists
		File f = new File(workingDir, username);
		if (f.exists() && f.isDirectory()) {
			return "Username already in use. Please pick a different username.";
		}

		// create the account with the given password
		if (f.mkdir()) {
			// add salt to the password
			String salt = encode64(getSalt());
			password = hash(salt + password);

			for (int i = 0; i < HASH_ITERATIONS; i++) {
				password = hash(password);
			}

			// write salt and salted and hashed password
			File pwf = new File(workingDir, username + "/pw");
			BufferedWriter writer = new BufferedWriter(
					new OutputStreamWriter(new FileOutputStream(pwf), StandardCharsets.UTF_8));
			writer.write(salt + "\n");
			writer.write(password + "\n"); // hashed password
			writer.write(email); // hashed email
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
		System.out.println("Creating key for " + username + " (hashed)");

		// check that we are not overwriting the password
		if (keyName.equals("pw")) {
			return "Key name cannot be \"pw\", please choose a different key name";
		}

		// check that we are not creating a directory
		if (keyName.contains("/") || keyName.contains("..")) {
			return "Key name cannot be a directory, please choose a different key name";
		}

		// check if this username exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Cannot find your key. Message may have been corrupted. Try again or reconnect to server";
		}

		// create the keyName file with the given key
		File pwf = new File(f, keyName);
		BufferedWriter writer = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(pwf), StandardCharsets.UTF_8));
		writer.write(encryptData(key));
		System.out.println(key);
		writer.close();
		return "Successfully created a new key";
	}

	protected String listKeys(String username) throws Exception {
		// check if this username exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Directory not found. Message may have been corrupted. Try again or reconnect to server";
		}
		try {
			// final list of all key names
			String allKeys = "";

			// retrieve the file containing all the keys for this user
			File keyFile = new File(workingDir, username);
			String[] keyNames = keyFile.list();

			for (String keyName : keyNames) {
				if (!keyName.equals("pw") && !keyName.equals("log")) {
					allKeys += keyName + ", ";
				}
			}
			return "Key name options are: " + allKeys;
		} catch (Exception e) {
			return "A problem occurred while retrieving the key names";
		}
	}

	/**
	 * loads a key from the system
	 * 
	 * @param username
	 * @param keyName
	 * @return
	 * @throws Exception
	 */
	protected String loadKey(String username, String keyName) throws Exception {
		// check if this username exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Directory not found. Message may have been corrupted. Try again or reconnect to server";
		}

		try {
			// retrieve the file containing the key
			File keyFile = new File(workingDir, username + "/" + keyName);
			Scanner keyReader = new Scanner(keyFile);
			String encryptedKey = keyReader.nextLine();
			keyReader.close();

			// send the decrypted key's content back to client
			String savedKey = decryptData(encryptedKey);
			return "Success! The requested key is: " + savedKey;
		} catch (FileNotFoundException e) {
			return "No such key, try running \"create key\" first";
		} catch (Exception e) {
			return "A problem occurred while retrieving the key's content";
		}
	}

	protected String deleteKey(String username, String keyName) {
		// check if this username exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Directory not found. Message may have been corrupted. Try again or reconnect to server";
		}

		// retrieve the file containing the key
		File keyFile = new File(workingDir, username + "/" + keyName);
		if (keyFile.exists()) {
			if (keyFile.delete())
				return "Key successfully deleted";
			else
				return "Failed to delete file for unknown reasons";
		} else
			return "Key not found. Please check your spelling (case-sensitive) or run \"list keys\" first.";
	}

	protected String changePassword(String username, String newPassword, String oldPassword) {
		// check if this username exists
		File f = new File(workingDir, username);
		if (!f.exists() || !f.isDirectory()) {
			return "Directory not found. Message may have been corrupted. Try again or reconnect to server";
		}
		try {

			// verify the old password is correct
			File passwordFile = new File(workingDir, username + "/pw");
			Scanner passwordReader = new Scanner(passwordFile);
			String savedSalt = passwordReader.nextLine();
			String savedPassword = passwordReader.nextLine();
			String savedEmail = passwordReader.nextLine();
			passwordReader.close();

			oldPassword = hash(savedSalt + oldPassword);
			for (int i = 0; i < HASH_ITERATIONS; i++) {
				oldPassword = hash(oldPassword);
			}
			// quit if passwords don't match
			if (!savedPassword.equals(oldPassword)) {
				return "Incorrect password, no changes made";
			}
			setPassword(username, newPassword, savedEmail);
			return "Successfully changed password";
		} catch (Exception e) {
			return "A problem occurred while changing password";
		}
	}

	protected boolean verifyEmail(String username, String email) throws Exception {
		File passwordFile = new File(workingDir, username + "/" + "pw");
		Scanner reader = new Scanner(passwordFile);
		reader.nextLine(); // throw away salt
		reader.nextLine(); // throw away password
		String savedEmail = reader.nextLine();
		reader.close();
		return hash(email).equals(savedEmail);
	}

	protected void setPassword(String username, String newPassword, String email) throws Exception {

		// salt and hash the new password
		String salt = encode64(getSalt());
		newPassword = hash(salt + newPassword);

		for (int i = 0; i < HASH_ITERATIONS; i++) {
			newPassword = hash(newPassword);
		}

		// retrieve the file containing all the keys for this user
		File userDirectory = new File(workingDir, username);
		String[] keyNames = userDirectory.list(); // list of all keys to be re-encrypted

		// get the new encryption key from the new password
		SecretKey newEncryptionKey = keyFromPassword(newPassword);

		for (String keyName : keyNames) {
			if (!keyName.equals("pw")) {
				File keyFile = new File(workingDir, username + "/" + keyName);
				Scanner keyReader = new Scanner(keyFile);
				String encryptedKey = keyReader.nextLine();
				keyReader.close();
				String savedKey = decryptData(encryptedKey);

				BufferedWriter writer = new BufferedWriter(
						new OutputStreamWriter(new FileOutputStream(keyFile), StandardCharsets.UTF_8));
				writer.write(""); // delete the old encrypted key
				writer.write(encryptData(savedKey, newEncryptionKey)); // replace with new encrypted key
				writer.close();
			}
		}

		// change password file and password for the current session
		// write salt and salted and hashed password
		File pwf = new File(workingDir, username + "/pw");
		BufferedWriter writer = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(pwf), StandardCharsets.UTF_8));
		writer.write(salt + "\n");
		writer.write(newPassword + "\n"); // hashed password
		writer.write(email);
		writer.close();
		setEncryptionKey(newPassword);
	}

	protected boolean verifyOTP(String email) throws Exception {
		String otp = generateOTP();
		sendEmail(email, otp);
		sendMessage("email sent");
		try {
			ScheduledExecutorService executor = Executors.newScheduledThreadPool(2);
			final Future<Boolean> handler = executor.submit(new Callable<Boolean>() {
				public Boolean call() throws Exception {
					String input = readResponse();
					if (input.startsWith("OTP"))
						input = input.split(" ")[1];
					if (input.equals(otp))
						return true;
					return false;
				}
			});
			executor.schedule((Runnable) () -> handler.cancel(true), OTP_LIMIT, TimeUnit.MINUTES);
			return handler.get();
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Determines whether this log-in requires OTP verification
	 * and set lastLogin to the last log-in record
	 * @param username
	 * @throws IOException 
	 */
	protected boolean checkLog(String username) {
		try {
			File logfile = new File(workingDir, username+"/log");
			FileReader fr = new FileReader(logfile);
			BufferedReader br = new BufferedReader(fr);
			String line, lastline = "";
			boolean status = true;
			while((line=br.readLine()) != null) {
				line = decryptData(line).trim();
				String old_ip = line.split(" on ")[0];
				if(old_ip.equals(ip)) {
					status = false;
				}
				lastline = line;
			}
			if(!lastline.equals(""))
				lastLogin = "Your last log-in was from "+lastline;
			else
				lastLogin = "First log-in to this account";
			br.close();
			return status;
		} catch(Exception e) {
			lastLogin = "First log-in to this account";
			return true;
		}
	}
	
	protected String secondFactor(String username) throws Exception {
		boolean otp = checkLog(username);
		String response = "Successfully logged in\n"+lastLogin;
		if(otp){
			sendMessage("Requires email verification");
			
			// confirm email
			String msg = readResponse();
			System.out.println(msg);
			if(!msg.startsWith("TOEMAIL")) return "Message corrupted";
			String email = msg.split(" ")[1];
			if(!verifyEmail(username, email)) return "Invalid or incorrect email";
			if(!verifyOTP(email))
				 return "Email verification failed";
		}
		
		// write log-in log entry
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
	    String date = dateFormat.format(new Date());
		String log_entry = encryptData(ip +" on "+date)+"\n";
		Path filepath = Paths.get(workingDir.getAbsolutePath(), username, "log");
		try {
			Files.createFile(filepath);
		} catch(FileAlreadyExistsException e) {} // file already exists
		Files.write(filepath, log_entry.getBytes(), StandardOpenOption.APPEND);
		
		return response;
	}

	/*------------------------------------------
	 * IO HELPER FUNCTIONS
	 ------------------------------------------*/

	protected void sendEmail(String to, String otp) {
		// Sender's email ID needs to be mentioned
		String from = "181s.safeguard@gmail.com";
		final String username = from;
		final String password = "alex&mui";

		Properties prop = new Properties();
		prop.put("mail.smtp.auth", "true");
		prop.put("mail.smtp.host", "smtp.gmail.com");
		prop.put("mail.smtp.port", "587");
		prop.put("mail.smtp.starttls.enable", "true");

		// Get the Session object.
		Session session = Session.getInstance(prop, new javax.mail.Authenticator() {
			protected PasswordAuthentication getPasswordAuthentication() {
				return new PasswordAuthentication(username, password);
			}
		});

		try {
			Message message = new MimeMessage(session);
			message.setFrom(new InternetAddress(from));
			message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
			message.setSubject("Your OTP for safeguard");
			message.setText("Hello,\n\nThis is your OTP: " + otp
					+ "\nIt will only be valid for three minutes.\n\nSafeguard Team");
			Transport.send(message);
			System.out.println("Email successfully sent to " + to);
		} catch (MessagingException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Returns a random 8-character OTP
	 */
	public static String generateOTP() {
		SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[8];
		random.nextBytes(bytes);
		return encode64(bytes);
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

	/*------------------------------------------
	 * CRYPTOGRAPHIC HELPER FUNCTIONs
	 ------------------------------------------*/

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
		sharedKey = decode64(key);

		return valid_message;
	}

	/**
	 * Returns the certificate (public key + signature) as a string
	 */
	protected String getCertificate() throws Exception {
		// generate public/private key
		Gen gen = new Gen();
		gen.generateSigningKey("A");
		gen.generateEncrptionKey("B");
		Key privKeyA = Gen.getKeyFromFile("A", "sk", "DSA");
		String privA = encode64(privKeyA.getEncoded());
		Key pubKeyB = Gen.getKeyFromFile("B", "pk", "RSA");
		String publicB = encode64(pubKeyB.getEncoded());
		
		String keys = publicB + " " + privA;

		// sign with CA secret key
		PrivateKey signKeyCA = (PrivateKey) Gen.getKeyFromFile("CA", "sk", "DSA");
		Signature sign = Signature.getInstance("SHA256withDSA");
		sign.initSign(signKeyCA);
		sign.update(keys.getBytes("UTF-8"));
		String signature = encode64(sign.sign());
		
		return keys + "," + signature;
	}

	/**
	 * Encoder from bytes to Base64 string (avoids slash)
	 * 
	 * @param bytes
	 * @return encoded string
	 */
	private static String encode64(byte[] bytes) {
		String str = Base64.getMimeEncoder().encodeToString(bytes);
		return str.replace("/", "_");
	}

	/**
	 * Decode Base64 string to byte[]
	 * 
	 * @param base64 string (possibly with _ but no /)
	 * @return decode bytes
	 */
	private static byte[] decode64(String str) {
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
	 * Creates a random salt
	 *
	 * @return 16-byte salt
	 */
	public static byte[] getSalt() {
		byte[] salt = new byte[16];
		Random random = new SecureRandom();
		random.nextBytes(salt);
		return salt;
	}

	/**
	 * Convert a password into an encryption key
	 * 
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
	}

	private SecretKey keyFromPassword(String password) throws Exception {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), saltPB, 1024, 256);
		SecretKey tmp = factory.generateSecret(spec);
		dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		return new SecretKeySpec(tmp.getEncoded(), "AES");
	}

	public String encryptData(String data) throws Exception {
		dcipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivPB);
		byte[] utf8EncryptedData = dcipher.doFinal(data.getBytes("UTF-8"));
		return encode64(utf8EncryptedData);
	}

	public String encryptData(String data, SecretKey tempKey) throws Exception {
		dcipher.init(Cipher.ENCRYPT_MODE, tempKey, ivPB);
		byte[] utf8EncryptedData = dcipher.doFinal(data.getBytes("UTF-8"));
		return encode64(utf8EncryptedData);
	}

	public String decryptData(String encrypted) throws Exception {
		dcipher.init(Cipher.DECRYPT_MODE, encryptionKey, ivPB);
		byte[] decryptedData = decode64(encrypted);
		byte[] utf8 = dcipher.doFinal(decryptedData);
		return new String(utf8, "UTF-8");
	}

	public void setDirectory(String dir) {
		workingDir = new File(dir);
	}

	public void setEncKeyTesting(String password) throws Exception {
		encryptionKey = keyFromPassword(password);
	}

	public static void main(String[] args) {

	}
}
