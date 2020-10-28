/**
 * 
 */
package safeguard;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * @author
 *
 */
public class Gen {

	private static final int KEY_LENGTH = 2048;

	public Gen() {

	}

	public void generateSigningKey(String filename) throws NoSuchAlgorithmException, NoSuchProviderException {
		// Creating KeyPair generator object
		SecureRandom random = new SecureRandom();
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
		keyPairGen.initialize(KEY_LENGTH, random);

		// Generating the pair of keys
		KeyPair pair = keyPairGen.generateKeyPair();

		// Getting keys from the key pair
		PrivateKey privKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();

		try {
			FileOutputStream fos = new FileOutputStream(filename + ".pk");
			fos.write(publicKey.getEncoded());
			fos.close();
			//System.out.println("Successfully wrote public key.");

			fos = new FileOutputStream(filename + ".sk");
			fos.write(privKey.getEncoded());
			fos.close();
			//System.out.println("Successfully wrote private key");

		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	}

	public void generateEncrptionKey(String filename) throws NoSuchAlgorithmException, NoSuchProviderException {
		// Creating KeyPair generator object
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		SecureRandom random = new SecureRandom();
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGen.initialize(KEY_LENGTH, random);

		// Generating the pair of keys
		KeyPair pair = keyPairGen.generateKeyPair();

		// Getting keys from the key pair
		PrivateKey privKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();

		try {
			FileOutputStream fos = new FileOutputStream(filename + ".pk");
			fos.write(publicKey.getEncoded());
			fos.close();
			//System.out.println("Successfully wrote public key.");

			fos = new FileOutputStream(filename + ".sk");
			fos.write(privKey.getEncoded());
			fos.close();
			//System.out.println("Successfully wrote private key");

		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
	}
	
	/**
	 * Method for retrieving a key from a file
	 * 
	 * @param name
	 * @param postfix
	 * @return Key object extracted from the given file
	 * @throws Exception
	 */
	protected static Key getKeyFromFile(String name, String postfix, String type) throws Exception {
		File f = new File(name + '.' + postfix);
		DataInputStream dis = new DataInputStream(new FileInputStream(f));
		byte[] keyBytes = new byte[(int) f.length()];
		dis.readFully(keyBytes);
		dis.close();

		KeyFactory kf = KeyFactory.getInstance(type);

		if (postfix == "sk") {
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			return kf.generatePrivate(spec);
		} else if (postfix == "pk") {
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			return kf.generatePublic(spec);
		}
		return null;
	}

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		Gen gen = new Gen();
		gen.generateEncrptionKey("B");
		gen.generateSigningKey("A");
	}
}
