package safeguard;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ServerThreadTest {
	private ServerThread thread;
	private File workingDir;
	private String username, password, email;

	@BeforeEach
	void setUp() throws Exception {
		thread = new ServerThread();
		thread.setDirectory("users");
		workingDir = new File("users");

		username = "user";
		password = "treehouse14";
		email = "user@gmail.com";
	}

	@Test
	void testLogin() throws Exception {
		// assume createUser is correct for login test
		thread.createUser(username, password, email);

		// correct password
		String response = thread.login(username, password);
		assertEquals(response, "Successfully logged in");

		// incorrect password
		response = thread.login(username, "password");
		assertEquals(response, "Invalid credentials");

		// incorrect username
		response = thread.login("hello", password);
		assertEquals(response, "Invalid username");

		// delete all testing keys made
		File userFile = new File(workingDir, username);
		String[] entries = userFile.list();
		for (String s : entries) {
			File currentFile = new File(userFile.getPath(), s);
			currentFile.delete();
		}
		userFile.delete();
	}

	@Test
	void testCreateUser() throws NoSuchAlgorithmException, IOException {
		// create a user successfully
		String response = thread.createUser(username, password, email);
		assertEquals(response, "Successfully created an account.");

		// try to create the same user
		response = thread.createUser(username, password, email);
		assertEquals(response, "Username already in use. Please pick a different username.");

		// delete all testing keys made
		File userFile = new File(workingDir, username);
		String[] entries = userFile.list();
		for (String s : entries) {
			File currentFile = new File(userFile.getPath(), s);
			currentFile.delete();
		}
		userFile.delete();
	}

	@Test
	void testCreateKey() throws Exception {
		thread.createUser(username, password, email);
		thread.setEncKeyTesting(password);
		thread.setDirectory("users");

		// cannot create key with name "pw"
		String response = thread.createKey(username, "pw", "123");
		assertEquals(response, "Key name cannot be \"pw\", please choose a different key name");

		// cannot create key with name that is a directory
		response = thread.createKey(username, "../username/email", "123");
		assertEquals(response, "Key name cannot be a directory, please choose a different key name");

		// create a key successfully
		response = thread.createKey(username, "bank", "123");
		assertEquals(response, "Successfully created a new key");

		// delete all testing keys made
		File userFile = new File(workingDir, username);
		String[] entries = userFile.list();
		for (String s : entries) {
			File currentFile = new File(userFile.getPath(), s);
			currentFile.delete();
		}
		userFile.delete();
	}

	@Test
	void testListKeys() throws Exception {
		thread.createUser(username, password, email);
		thread.setEncKeyTesting(password);
		thread.setDirectory("users");

		// list no keys when none have been created
		String response = thread.listKeys(username);
		assertEquals(response, "Key name options are: ");

		thread.createKey(username, "bank", "123");
		thread.createKey(username, "email", "123");
		thread.createKey(username, "password", "123");

		// list all keys when they exists
		response = thread.listKeys(username);
		assertTrue(response.contains("password"));
		assertTrue(response.contains("bank"));
		assertTrue(response.contains("email"));

		// delete all testing keys made
		File userFile = new File(workingDir, username);
		String[] entries = userFile.list();
		for (String s : entries) {
			File currentFile = new File(userFile.getPath(), s);
			currentFile.delete();
		}
		userFile.delete();
	}

	@Test
	void testLoadKey() throws Exception {
		thread.createUser(username, password, email);
		thread.setEncKeyTesting(password);
		thread.setDirectory("users");

		thread.createKey(username, "bank", "123");

		// non-existent key
		String response = thread.loadKey(username, "email");
		assertEquals(response, "No such key, try running \"create key\" first");

		// successfully load key
		response = thread.loadKey(username, "bank");
		assertEquals(response, "Success! The requested key is: 123");

		// delete all testing keys made
		File userFile = new File(workingDir, username);
		String[] entries = userFile.list();
		for (String s : entries) {
			File currentFile = new File(userFile.getPath(), s);
			currentFile.delete();
		}
		userFile.delete();
	}

	@Test
	void testDeleteKey() throws Exception {
		thread.createUser(username, password, email);
		thread.setEncKeyTesting(password);
		thread.setDirectory("users");

		thread.createKey(username, "bank", "123");

		// successfully run the method
		String response = thread.deleteKey(username, "bank");
		assertEquals(response, "Key successfully deleted");

		// list keys should be empty
		response = thread.listKeys(username);
		assertEquals(response, "Key name options are: ");

		// delete all testing keys made
		File userFile = new File(workingDir, username);
		String[] entries = userFile.list();
		for (String s : entries) {
			File currentFile = new File(userFile.getPath(), s);
			currentFile.delete();
		}
		userFile.delete();
	}

	@Test
	void testChangePassword() throws Exception {
		thread.createUser(username, password, email);
		thread.setEncKeyTesting(password);
		thread.setDirectory("users");

		// change password with incorrect old password
		String response = thread.changePassword(username, password + "a", "incorrect");
		assertEquals(response, "Incorrect password, no changes made");

		// change password successfully
		response = thread.changePassword(username, password + "a", password);
		assertEquals(response, "Successfully changed password");

		response = thread.login(username, password + "a");
		assertEquals(response, "Successfully logged in");

		// delete all testing keys made
		File userFile = new File(workingDir, username);
		String[] entries = userFile.list();
		for (String s : entries) {
			File currentFile = new File(userFile.getPath(), s);
			currentFile.delete();
		}
		userFile.delete();
	}
}
