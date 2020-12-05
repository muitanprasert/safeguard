package password;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PasswordStrengthTest {
	String strongPassword = "treehouse14";
	String weakPassword = "password123";

	@Test
	void testPasswordStrength() throws IOException {
		PasswordStrength checker = new PasswordStrength();
		checker = new PasswordStrength(weakPassword);
		checker = new PasswordStrength(strongPassword);
	}

	@Test
	void testCheck_strength() throws IOException {
		PasswordStrength checker = new PasswordStrength();
		assertTrue(!checker.check_strength(weakPassword));
		assertTrue(checker.check_strength(strongPassword));
	}

}
