# safeguard
Centralized server-based password manager with support for multi-factor authentication

_Current status_
* Registration implemented and roughly tested
* Requirements document ready for M2; others partially edited
* Log-in
* Key creation and loading
* Secure channels
* Encrypted password files on server
* Now supports key content with spaces

_Issues_
* For usability, it might be more reasonable to not hash key names so that we'd be able to list them for the user.
* Currently relies on running Gen to create CA keys and ensure users/ directory exists.


_Running Instructions_
* In the safeguard directory run
* `javac Server.java`
* `javac Client.java`
* to compile the server and client files.
* Then move out to src directory and run
* `java safeguard.Server`
* `java safeguard.Client`
* to start up the client and server

contentsOfKey:
IQWRLCEVYRkQOahIVaw0IQ==
1ED9umYMOLOJVSP8gV0e1Q==

[B@71bbbadc