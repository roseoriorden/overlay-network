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
def tcp_client(port, data, server_ip):
    # Initialize a TCP client socket using SOCK_STREAM
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cntx.load_verify_locations('cert.pem')
    cntx.load_cert_chain('cert.pem')

    s = cntx.wrap_socket(s, server_hostname='test.server')
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
    print("Bytes Sent:     {data}")
    print(f"Bytes Received: {received.decode()}")

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
                    return
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

#######################################
#               Driver                #
#######################################
def communication_manager():
    global server_ip
    # find own ip
    init_ip()

    bcast_port = 1337
    tcp_port = 9990

    # broadcast to other users that you exist
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.bind(('', bcast_port))
    broadcast_listener(broadcast_socket)
    
    while True:
        tcp_client(tcp_port, input("Enter message to send: "), server_ip)
    
#######################################
#               Main                  #
#######################################
def main():
    communication_manager()


if __name__ == "__main__":
    main()
