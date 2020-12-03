# safeguard
Centralized server-based password manager with support for multi-factor authentication

_Functionalities_
* Registration
* Log-in (with email verification)
* Key creation, loading, and deletion
* Secure channels
* Encrypted all non-hashed files on server
* Supports key content with spaces and usernames with slashes
* Tested on our machines (Windows and Linux) as well as Pomona VM.

_Running Instructions_
1. Running from JAR files in /executables (recommended)
* Installation:
  * Go to /executables directory and run `java -jar gen.jar` to create CA keys.
  * Copy `client.jar` and `CA.pk` to the client's machine.
  * Copy `server.jar` and `CA.sk` to the server's machine.
* To run the server, go to the directory containing `server.jar` and run `java -jar server.jar`.
* To run the server, go to the directory containing `client.jar` and run `java -jar client.jar (host)`. If host is not specified, client tries to connect to localhost.
2. Running from source codes (assuming server and client on the same machine)
* In the /src/safeguard directory, run the following commands to compile all necessary classes.
  * `javac Server.java`
  * `javac Client.java`
  * `javac Gen.java`
* To set up, move out of /src and run `java safeguard.Gen`.
* Run the the following commands to start up the server and connect to it as a client.
  * `java safeguard.Server`
  * `java safeguard.Client`
