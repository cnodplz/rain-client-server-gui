#!/usr/bin/env python3
import re
import fileinput
import socketserver
import socket
import sys
import os
import subprocess

def procs(x="all_argv_files", y=0):
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
    print(x, sys.argv, y)
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
        print("-----{}-----".format(iptype))
        for ipv4_list2 in sorted(d.keys()):
            if d[ipv4_list2] > 1:
                print("({1: <3}) {0: <24} {2: <64}".format(ipv4_list2, d[ipv4_list2], subprocess.getoutput("dig +short -x {0}".format(ipv4_list2))))
                '''print("({1: <3}) {0: <24} {2: <64}".format(ipv4_list2, d[ipv4_list2], "{}".format(out)))'''
                ctr+=1
            elif d[ipv4_list2] == 1:
                print("({1: <3}) {0: <24} {2: <64}".format(ipv4_list2, d[ipv4_list2], subprocess.getoutput("dig +short -x {0}".format(ipv4_list2))))
        print("TOTAL FOUND: {0}".format(len(results2)))
    except:
        print("No Address Found.")

class console:
    def __init__(self):
        self.deflog = [] 
    def saveit(self, a=''):
        self.deflog.append(a)
    def printit(self):
        for x in self.deflog:
            print("[+]    {:<80}".format(x))
         

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        print("[{}]: <{}>".format(self.client_address[0], self.data))
        # just send back the same data, but upper-cased
        self.request.sendall(self.data.upper())

def main():
    con1 = console()
    print(b"\uD83D\uDE02".decode("utf-16"))
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
    subprocess.call(["date"])
    print("args: {}\n\n_________________ARGS_________________\nServer: ./spy.py -s <host ip> <port #>\nClient: ./spy.py -c <host ip> <port #>\nFile_Search_IP: ./spy.py -f <filename>\n".format(' '.join(sys.argv[1:])))
    con1.saveit("{:-^80}".format(sys.argv[0]))
    if len(sys.argv) >= 2:
        try:
            if sys.argv[1] == '-s':
                serverip = str(sys.argv[2])
                serverport = int(sys.argv[3])
                server = socketserver.TCPServer((serverip, serverport), MyTCPHandler)
                con1.saveit("Server started >>> {}:{}".format(serverip, serverport))
                server.serve_forever()
            elif sys.argv[1] == '-c':
                clientip = str(sys.argv[2])
                clientport = int(sys.argv[3])
                clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                con1.saveit("Connected: <{} {}>\n\nclient> ".format(clientip, clientport))
                clientsocket.connect((clientip, clientport))
                x = str(input())
                con1.saveit(clientsocket.send(bytes(x, 'UTF-8')))
                received = str(clientsocket.recv(1024), "utf-8")
                con1.saveit(received)
                clientsocket.close()
            # Needs fixed, fileinput hangs in function, readline, EOF
            '''elif sys.argv[1] == '-f':
                sys.argv = sys.argv[2:]
                print(fileinput.input(), sys.argv)
                procs(fileinput.input(), 4)'''
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
    procs(fileinput.input(), 4)
    procs(fileinput.input(), 6)
    '''

    # test junk
    con1.saveit(mess)
    con1.saveit(mess2)
    con1.saveit("A string of thing")
    con1.printit()
    #print("-----{}-----".format(sys.argv[0]))

if __name__ == '__main__':
    main()
