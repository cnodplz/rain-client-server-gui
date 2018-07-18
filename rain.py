#!/usr/bin/env python3
import base64
import csv
import datetime
import fileinput
import numpy
import os
import random
import re
import socket
import socketserver
import subprocess
import sys
import threading
from time import gmtime, strftime, localtime

'''
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
'''

class console:

    def __init__(self):
        self.deflog = []
        self.logfile = ""

    def saveit(self, a=''):
        self.deflog.append(a)

    def logit(self):
        self.logfile = "{}-{}".format(sys.argv[0], strftime("%Y%m%d", localtime()))
        with open(self.logfile, 'a+') as x:
            for y in self.deflog:
                x.write("[{}] {}: {}\n".format(strftime("%H:%M:%S", localtime()), __name__, y))
        self.saveit("[Logged to file --> {}]".format(self.logfile))

    def printit(self):
        for x in self.deflog:
            print("[+] [{}]: // {:<80}\n".format(strftime("%H:%M:%S", localtime()),x))

class crypter:

    def __init__(self):
        self.crypted_strings = []
        self.crypted_logfile = ""
        self.decrypted_strings = []
        self.decrypted_logfile = ""

    def crypto_saveit(self, a=''):
        self.crypted_strings.append(a)
    
    def crypto_logit(self):
        self.crypted_logfile = 'crypto'
        with open(self.crypted_logfile, 'wb') as x:
            for y in self.crypted_strings:
                '''y.encode('utf-8')'''
                base64.b64encode(y)
                x.write(y)

    def crypto_printit(self):
        for x in self.crypted_strings:
            print("[+] [{}]: // {:<80}\n".format(strftime("%H:%M:%S", localtime()),str(x)))

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        handlog = console()
        cryptlog = crypter()
        self.data = self.request.recv(1024).strip()
        handlog.saveit("[{}]: <{}>".format(self.client_address[0], self.data))
        handlog.logit()
        handlog.printit()
        cryptlog.crypto_saveit(self.data)
        cryptlog.crypto_logit()
        cryptlog.crypto_printit()
        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())

class secutils:

    def __init__(self):
        pass

    def threads(console):
        #con3 = console()
        x = console
        thread1 = threading.Thread(group=None, target=None, name=None, args=(), kwargs={}, daemon=None)
        thread2 = threading.Thread(group=None, target=None, name=None, args=(), kwargs={}, daemon=None)
        thread1.start()
        thread2.start()
        x.saveit("threads_active: {0} - {1}".format(threading.active_count(), threading.get_ident()))
        x.saveit("Thread1: {0} Thread2: {1}".format(thread1.is_alive(), thread2.is_alive()))
        x.saveit(thread1.is_alive())
        x.saveit(thread2.is_alive())

    def iptrack(x="all_argc_files", y=0):
        con2 = console()
        ipv4 = ''
        ipv6 = ''
        iptype = ''
        ipstring = ''
        if y == 4:
            ipv4=re.compile("((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])", re.MULTILINE)
            iptype = "IPv4"
            ipstring = ipv4
        if y == 6:
            ipv6=re.compile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0    -9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA    -F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1    }[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))", re.MULTILINE)
            iptype = "IPv6"
            ipstring = ipv6
        fn2 = x.filename()
        results = []
        results1 = []
        results2 = []
        d = 0
        atr = 0
        ctr = 0
        con2.saveit("{} {} {}".format(x, sys.argv, y))
        for line in x:
            fn1 = x.filename()
            ipv4_list = re.search(ipstring, line)
            ipv4_list2 = re.findall(ipstring, line)
            if ipv4_list2:
                results2.append(ipv4_list2)
            if ipv4_list:
                results.append(ipv4_list.group(0))
                d = {x3:results.count(x3) for x3 in results}
                if fn1 != fn2:
                    d.update({fn1:fn1})
                    del results[1:]
                    fn2 = fn1
        try:
            con2.saveit("-----{}-----".format(iptype))
            for ipv4_list2 in sorted(d.keys()):
                if d[ipv4_list2] > 1:
                    con2.saveit("({1: <3}) {0: <24} {2: <64}".format(ipv4_list2, d[ipv4_list2], subprocess.getoutput("dig +short -x {0}".format(ipv4_list2))))
                    '''print("({1: <3}) {0: <24} {2: <64}".format(ipv4_list2, d[ipv4_list2], "{}".format(out)))'''
                    ctr+=1
                elif d[ipv4_list2] == 1:
                    con2.saveit("({1: <3}) {0: <24} {2: <64}".format(ipv4_list2, d[ipv4_list2], subprocess.getoutput("dig +short -x {0}".format(ipv4_list2))))
            con2.saveit("TOTAL FOUND: {0}".format(len(results2)))
            con2.printit()
        except:
            con2.saveit("No Address Found.")
            con2.printit()

def main():

    con1 = console()
    # print(b"\uD83D\uDE02".decode("utf-16"))
    con1.saveit(b"\uD83D\uDE02".decode("utf-16"))
    # main vars
    serverip = 0
    serverport = 0
    clientip = 0
    clientport = 0
    menuitems = 999
    mess="message"
    mess2='loggg'

    # catch args // argparse module seems bad
    print("{:+^40}\nSERVER: ./rain.py -s <host ip> <port #>\nCLIENT: ./rain.py -c <host ip> <port #>\nIPv4/6: ./rain.py -f <filename>\nARGS: {}\n".format(sys.argv[0], ' '.join(sys.argv[1:])))
    # con1.saveit("{:-^80}".format(sys.argv[0]))
    subprocess.call(["date"])
    if len(sys.argv) >= 2:
        try:
            if sys.argv[1] == '-s':
                serverip = str(sys.argv[2])
                serverport = int(sys.argv[3])
                server = socketserver.TCPServer((serverip, serverport), MyTCPHandler)
                con1.saveit("Server started >>> {}:{}".format(serverip, serverport))
                con1.printit()
                con1.logit()
                server.serve_forever()
            elif sys.argv[1] == '-c':
                clientip = str(sys.argv[2])
                clientport = int(sys.argv[3])
                clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                con1.saveit("Connected: <{} {}>".format(clientip, clientport))
                clientsocket.connect((clientip, clientport))
                x = str(input())
                con1.saveit(clientsocket.send(bytes(x, 'UTF-8')))
                received = str(clientsocket.recv(1024), "utf-8")
                con1.saveit(received)
                clientsocket.close()
                con1.saveit("client connection closed.")
                con1.logit()
            # Needs fixed, fileinput hangs in function, readline, EOF
            '''elif sys.argv[1] == '-f':
                sys.argv = sys.argv[2:]
                secutils.iptrack(fileinput.input(), 4)'''
        except:
            raise
            con1.saveit("Usage:\nprogram [-s, --server] <hostname> <port>\nprogram [-c --client] <hostname> <port>\n\nException: {}\n".format(sys.exc_info()[0]))

    # all main
    '''while menuitems != 0:
        print("[ MENU: {} ]\n1: opt 1\n2: opt 2\n3: opt 3\n4: opt 4\n5: opt 5\n0: quit()\n".format    (sys.argv[0]))
        menuitems = int(input())
        if menuitems == 1:
            pass
        elif menuitems == 2:
            pass
        elif menuitems == 3:
            pass
        elif menuitems == 4:
            pass
        elif menuitems == 5:
            pass
        elif menuitems == 0:
            sys.exit()
            break
        else:
            print("bye")'''

    # fileinput iterates over lines from multiple input streams ie sys.argv[1:] defaulting to sys.stin if the list is empty
    '''
    secutils(fileinput.input(), 4)
    secutils(fileinput.input(), 6)
    '''

    # test junk
    # secutils.threads(con1)
    # con1.saveit("test log")
    con1.logit()
    con1.printit()
    # secutils.threads()

if __name__ == '__main__':
    main()
