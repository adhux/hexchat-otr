
This is the XChat OTR plugin ported to Hexchat along with several bug fixes.

It depends on libotr 3.2.1 which is no longer available in Debian Testing and
Ubuntu 14.04. You can download it from here

    https://otr.cypherpunks.ca/libotr-3.2.1.tar.gz

and install it with the following commands

    sudo apt-get install libgcrypt11-dev
    tar xvfz libotr-3.2.1.tar.gz
    cd libotr-3.2.1
    ./configure
    make
    sudo make install


Then install hexchat-otr with these commands

    sudo apt-get install cmake libglib2.0-dev build-essential
    git clone https://github.com/adhux/hexchat-otr.git
    cd hexchat-otr
    cmake .
    make
    cp libhexchatotr.so ~/.config/hexchat/addons/


Future plans: fix the /me bug and add libotr 4.0.0 support.


