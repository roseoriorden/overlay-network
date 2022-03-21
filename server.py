#!/usr/bin/env python3
import sys
import ssl
import socket
import argparse
from time import sleep
import time
from multiprocessing import Process
from socketserver import BaseRequestHandler, TCPServer
import hashlib
from datetime import datetime

own_ip = None
server_ip = None


def init_ip():
    global own_ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    own_ip = s.getsockname()[0]
    s.close()


#######################################
#             TCP example             #
#######################################
class tcp_handler(BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        print("Echoing message from: {}".format(self.client_address[0]))
        print(self.data)
        self.request.sendall("ACK from server".encode())


def tcp_listener(port):
    host = own_ip
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cntx.load_cert_chain('cert.pem', 'cert.pem')

    server = TCPServer((host, port), tcp_handler)
    server.socket = cntx.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except:
        print("listener shutting down")
        server.shutdown()


#######################################
#          Broadcast Example          #
#######################################
def broadcast_sender(port):
    count = 0
    hash = get_bcast_hash()
    print("beginning to send broadcasts")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            #msg = hash + ' ' + get_current_seconds()
            msg = hash
            count += 1
            s.sendto(msg.encode('ascii'), ('255.255.255.255', port))
            sleep(5)
    except KeyboardInterrupt:
        pass
######################################
#          Helper functions          #
######################################
def get_bcast_hash():
    bcast_string = "overlay-network-broadcast"
    hash = hashlib.sha256(bcast_string.encode('utf-8')).hexdigest()
    return hash

def get_current_date_time():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def get_current_seconds():
    return str(time.time()).split('.')[0]

def print_server_ip():
    global server_ip
    server_ip = server_ip
    print("sever IP in helper func: " + str(server_ip))

#######################################
#               Driver                #
#######################################
def communication_manager():
    global server_ip
    # find own ip
    init_ip()

    bcast_port = 1337
    tcp_listen = 9990

    # broadcast to other users that you exist
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.bind(('', bcast_port))
    procs = []
    procs.append(Process(target=broadcast_sender,
                 name="broadcast_sender_worker",
                 args=(bcast_port,)))

    procs.append(Process(target=tcp_listener,
                 name="tcp_listener_worker",
                 args=(tcp_listen,)))

    try:
        for p in procs:
            print("Starting: {}".format(p.name))
            p.start()

    except KeyboardInterrupt:
        for p in procs:
            print("Terminating: {}".format(p.name))
            if p.is_alive():
                p.terminate()
                sleep(0.1)
            if not p.is_alive():
                print(p.join())


#######################################
#               Main                  #
#######################################
def main():
    communication_manager()


if __name__ == "__main__":
    main()
