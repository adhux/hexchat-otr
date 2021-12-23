HexChat OTR
===========

Adds off-the-record (OTR) support to HexChat.

Originally forked from irssi-otr and still a work in progress.

Installation
------------

### Dependencies

- glib
- gcrypt
- libotr4
- hexchat
- meson

#### User install

```sh
meson builddir -Dlocal_install=true
ninja -C builddir install
```

#### System install

```sh
meson builddir
ninja -C builddir
sudo ninja -C builddir install
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

	At this point you need to verify this is the person you think it is.

	- If you know their fingerprint and it is correct:

		```
		/otr trust
		```

	- If you have previously agreed on a shared secret:

		```
		/otr auth <shared secret>
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
