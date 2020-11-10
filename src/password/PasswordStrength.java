package password;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

/**
 * 
 * @author Mui, Alex
 *
 *         Common passwords from from
 *         https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt
 *         Common dictionary words from
 *         https://www.mit.edu/~ecprice/wordlist.10000
 * 
 */
public class PasswordStrength {

	/**
	 * Constructor and password strength checker
	 * 
	 * @throws IOException
	 */
	public PasswordStrength(String pw) throws IOException {
		if (check_strength(pw))
			System.out.println("strong");
		else
			System.out.println("weak");
	}
	
	/**
	 * Empty constructor
	 * @throws IOException
	 */
	public PasswordStrength() throws IOException {
	}

	/**
	 * Return true if strong, false if weak
	 * @param pw
	 * @return
	 * @throws IOException
	 */
	public boolean check_strength(String pw) throws IOException {

		// at least 8 characters
		if (pw.length() < 8)
			return false;

		// check against 3.5k dictionary words longer than 8 characters
		if (!check_wordlist(pw, "dictionary.txt"))
			return false;

		// check against 400k common passwords longer than 8 characters
		return check_wordlist(pw, "compromised.txt");
	}

	/**
	 * Check if pw is in the list the specified file
	 * 
	 * @param pw
	 * @param filename
	 * @return
	 * @throws IOException
	 */
	private boolean check_wordlist(String pw, String filename) throws IOException {
		BufferedReader br = new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream(filename), "UTF-8"));
		ArrayList<String> sb = new ArrayList<String>();
		String line;
		while ((line = br.readLine()) != null)
			sb.add(line);
		br.close();

		if (sb.contains(pw))
			return false;
		return true;
	}

	/**
	 * runs the password strength checker
	 * 
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {
		if (args.length < 1)
			System.out.println("Incorrect number of arguments");
		new PasswordStrength(args[0]);
	}
}
