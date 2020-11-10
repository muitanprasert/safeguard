/**
 * 
 */
package safeguard;

import java.io.BufferedInputStream;
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
public class Server {
	@SuppressWarnings("resource")
	public static void main(String args[]) {
		final int PORT_NUMBER = 2018;

		ServerSocket serverSocket = null;
		Socket socket = null;

		try {
			serverSocket = new ServerSocket(PORT_NUMBER);
			System.out.println("Server started at port " + PORT_NUMBER);
			
			while (true) {
				try {
					socket = serverSocket.accept();
					System.out.println("Client connected");
				} catch (IOException e) {
					System.out.println(e);
				}
				// new thread for the client
				new ServerThread(socket).start();
			}
		} catch (IOException e) {
			// print error if the server fails
			System.out.println("Server fails");
			System.out.println(e);
		}
	}
}
