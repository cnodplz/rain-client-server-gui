# rain-client-server-gui

    Summary:
    - client/server/decrypter/scripts in c, python, bash.
    - TCP/IP server prints connections in console, writes log, writes encrypted bytes from client to a file.
    - Decrypter just uses aes256 key and iv to decrypt bytes in hash file.
    - Client encrypts w/ aes256/openssl and sends bytes to server, can change to more practical encryption for lightweight client/remove dependecy on libraries.
    - bash files & executable - crain, srain, decrypter.exe
    - build: gcc -lssl -lcrypto <file.c> -o <file.exe>

    TODO:
    - Obfuscate code and signatures.
    - Replace library crypto dependencies with in-program functionality, reduce dependencies in general.
    - Scrub for bugs, useless code, memory use.
    - Use of tor w/ client? Server .onion + proxies.
    - Integrate other tools/binaries?
    - Take time to build out the functions in PyQt5 GUI

    SERVER - rain.py
    - serve_forever adds while loop preventing main program from completing fully, needs a clean exit to finish logs.
    - Server generates clients and encryption keys, tracks generated, active clients.
    - Server writes console and log.
    - Server writes encrypted data to file.
    - Server decrypts and prints data. -> Use of decrypter.c
    - Server sends commands to clients.  Add rshell, sysinfo pullback options.
    - Limit connections, use authentication

    CLIENT - client5.c
    - Server generates clients with unique id and public key, maintains key associations. tbd on openssl library dependance, key type, size etc.
    - Client public key to auth w/ server, key to encrypt data into file, send logs to server to decrypt.
    - Server able to track clients, send cmds.

    DECRYPTER - decrypter.c
    - Decrypts "crypto" file on server, update to work with upper limit of bytes.

    GUI - main4.py
    - Log view in pyqt5.

    GUI - seccons.py
    - Log view in pygame.
