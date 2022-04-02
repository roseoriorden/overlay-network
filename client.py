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
import ast
import json

own_ip = None
server_ip = None
ip_list = []

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
    print(f"Bytes Sent:     {data}")
    print(f"Bytes Received: {received.decode()}")

class tcp_handler(BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        ip = self.client_address[0]
        print("Echoing message from: " + ip + " ")
        print(self.data)
        self.request.sendall("ACK from server".encode())
        if b'PING' in self.data:
            pass
        elif b'PONG' in self.data:
            pass
        else:
            get_ip_host_lists(self.data)
            print_ips()

def print_ips():
    for i in ip_list:
        print(i)

def get_ip_host_lists(data):
    global ip_list
    # convert bytes to string which is already dict
    full_message = ast.literal_eval(data.decode('utf-8'))
    #print('type of clients_string' + str(type(clients_string)))
    # access dict which is value of outer dict ['msg']
    clients_string = full_message['msg']
    clients_dict = string_to_dict(clients_string)
    #print(clients_dict)
    #print(type(clients_dict))
    del clients_dict[own_ip]
    if len(clients_dict) == 0:
        print("You are the only client connected to the network!")
        return
    else:
        host_list = list(clients_dict.values())
        ip_list = list(clients_dict.keys())
        print_clients(host_list)

def print_clients(host_list):
    print("Current connections to the overlay network:")
    for host in host_list:
        print(host)

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
    return int(str(time.time()).split('.')[0])

def print_server_ip():
    global server_ip
    server_ip = server_ip

def retrieve_clients(tcp_port, server_ip):
    #msg = "retrieve"
    p = Packet("retrieve")
    tcp_client(tcp_port, p.get_packet(), server_ip)

def ping_clients(tcp_port, server_ip):
    #msg = "PING " + own_ip
    p = Packet("ping")
    for ip in ip_list:
        if ip != own_ip:
            print('pinging' + ip)
            tcp_client(tcp_port, p.get_packet(), server_ip)

def string_to_dict(string):
    #print("string to be converted: " + string + str(type(string)))
    d = json.loads(string)
    return d

######################################
#              Message               #
######################################
class Packet:
    def __init__(self, type):
        p_contents = { "type" : type }
                   #"msg" : msg }
        self.packet = json.dumps(p_contents)
    def get_packet(self):
        return self.packet

#######################################
#               Driver                #
#######################################
def communication_manager():
    global server_ip
    # find own ip
    init_ip()

    bcast_port = 1337
    tcp_port = 9995
    tcp_listen = 9990

    # broadcast to other users that you exist
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.bind(('', bcast_port))
    broadcast_listener(broadcast_socket)

    procs = []
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
    
    i = 0
    while True:
        if i % 2 == 0:
            print(str(i*5) + " call retrieve")
            retrieve_clients(tcp_port, server_ip)
        if i % 3 == 0:
            print(str(i*5) + " call ping")
            ping_clients(tcp_port, server_ip)
        sleep(5)
        i = i + 1

    while True:
        tcp_client(tcp_port, input("Enter message to send: "), server_ip)
    
#######################################
#               Main                  #
#######################################
def main():
    communication_manager()


if __name__ == "__main__":
    main()
