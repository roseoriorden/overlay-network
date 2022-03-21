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


def tcp_client(port, data, server_ip):
    # Initialize a TCP client socket using SOCK_STREAM
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cntx.load_verify_locations('cert.pem')
    cntx.load_cert_chain('cert.pem')

    s = cntx.wrap_socket(s, server_hostname='test.server')
    print("server IP in tcp_client: " + str(server_ip))
    print_server_ip()
    while server_ip:
        try:
            # Establish connection to TCP server and exchange data
            s.connect((server_ip, port))
            print('TCP connection established with ' + server_ip)
            s.sendall(data.encode())
            # Read data from the TCP server and close the connection
            received = s.recv(1024)
            break
        finally:
            s.close()
        break
    if not server_ip:
        print("no server IP found")
    if data:
        print("Bytes Sent:     {data}")
    else:
        print("No data sent")
    if received:
        print(f"Bytes Received: {received.decode()}")
    else:
        print("no data received")

#######################################
#          Broadcast Example          #
#######################################
def broadcast_listener(socket):
    global server_ip
    hash = get_bcast_hash()
    try:
        while True:
            data, addr = socket.recvfrom(512)
            if addr[0] != own_ip:
                string_rec = data.decode("utf-8")
                #substrings_rec = string_rec.split()
                if string_rec == hash:
                    server_ip = addr[0]
                    print("Broadcast received from " + server_ip)
                    print("server_ip in broadcast_listener: " + server_ip)
                    print_server_ip()
                    return server_ip
                    #now needs to connect with tcp server
                    #if int(substrings_rec[1]) >= int(get_current_seconds()) - 5 and int(substrings_rec[1]) <= int(get_current_seconds()):
                        #print("time validated")
                    
    except KeyboardInterrupt:
        pass


def broadcast_sender(port):
    count = 0
    hash = get_bcast_hash()
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
    tcp_port = 9995

    # broadcast to other users that you exist
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.bind(('', bcast_port))
    broadcast_listener(broadcast_socket)
    procs = []
    #procs.append(Process(target=broadcast_listener,
                         #name="broadcast_listener_worker",
                         #args=(broadcast_socket,)))

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
        while True:
            tcp_client(tcp_port, input("Enter message to send: "), server_ip)
            sleep(1)

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
