HexChat OTR
===========

Adds off the record support to HexChat.

Originally forked from irssi-otr and still a work in progress.

Installation
------------

### Dependencies

- glib
- gcrypt
- libotr4
- hexchat

```sh
./autogen.sh
make -s
sudo make install
```

Usage
-----

1. Start a session with a user:

	```
	/query nick
	/otr start
	```

	If this is your first time it may take a while to generate a key.

2. Authenticate this user:

	At this point you need to verify this is the person you think.

	- If you know their fingerprint and it is correct:

		```
		/otr trust
		```

	- If you have previously agreed on a password:

		```
		/otr auth <password>
		```

	- If you have neither of these:

		```
		/otr authq <question> <answer>
		```

3. Start chatting:

	Everything should be secure at this point.
	When you are done:

	```
	/otr finish
	```
