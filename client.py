#!/usr/bin/env python3
import ssl
import socket
from time import sleep
import time
from multiprocessing import Process, Manager
from socketserver import BaseRequestHandler, TCPServer
import hashlib
import ast
import json
import logging

manager = Manager()
shared_list = manager.list()
#logging.basicConfig(stream=sys.stdout, level=logging.INFO)

own_ip = None
server_ip = None
ip_list = []
clients_dict = {}
tcp_listen = 9990
tcp_port = 9995

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
            logging.info('TCP connection established with ' + server_ip)
            s.sendall(data.encode())
            # Read data from the TCP server and close the connection
            received = s.recv(1024)
            break
        finally:
            s.close()
        break
    logging.info(f"Bytes Sent:     {data}")
    logging.info(f"Bytes Received: {received.decode()}")

class tcp_handler(BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        ip = self.client_address[0]
        logging.info("Echoing message from: " + ip + " ")
        logging.info(self.data)
        self.request.sendall("ACK from server".encode())
        # decode message received
        full_message = ast.literal_eval(self.data.decode('utf-8'))
        m_type = full_message['type']
        logging.info(m_type)
        # if src ip not already in ip list, add it
        if ip != server_ip and ip not in shared_list:
            logging.info('adding ' + ip + ' to shared list')
            shared_list.append(ip)
        # if received ping, respond with pong
        if m_type == 'ping':
            if len(clients_dict) > 0 and ip in clients_dict:
                print('Received ping from ' + clients_dict[ip] + ' ... Replying with pong')
            else:
                print('Received ping from ' + ip + ' ... Replying with pong')
            p = Packet("pong")
            tcp_client(tcp_listen, p.get_packet(), ip)
        # if received pong, just print
        elif m_type == 'pong':
            if len(clients_dict) > 0 and ip in clients_dict:
                print('Received pong from ' + clients_dict[ip])
            else:
                print('Received pong from ' + ip)
        # else if received list of clients, update list
        elif m_type == 'connected':
            get_ip_host_lists(full_message)
            shared_list[:] = []
            for ip in ip_list:
                shared_list.append(ip)
                logging.info('added ' + ip + ' to the list')
            #print_ips()
        else:
            logging.info('received non-Packet format data')

def tcp_listener(port):
    host = own_ip
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cntx.load_cert_chain('cert.pem', 'cert.pem')

    server = TCPServer((host, port), tcp_handler)
    server.socket = cntx.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except:
        logging.info("listener shutting down")
        server.shutdown()


def print_ips():
    logging.info('in print_ips, shared_list is set ' + 
            str(len(shared_list)) + ' ' + str(shared_list))
    for i in shared_list:
        print(i)

def get_ip_host_lists(full_message):
    global ip_list
    # convert bytes to string which is already dict
    # access dict which is value of outer dict ['msg']
    clients_string = full_message['msg']
    global clients_dict
    clients_dict = string_to_dict(clients_string)
    if own_ip in clients_dict:
        del clients_dict[own_ip]
    if len(clients_dict) == 0:
        print("You are the only client connected to the network!")
        return
    else:
        host_list = list(clients_dict.values())
        logging.info('ip_list is set ' + str(len(ip_list)) + ' ' + str(ip_list))
        ip_list = list(clients_dict.keys())
        print_clients(host_list)

def print_clients(host_list):
    print("Current connections to the overlay network:")
    for host in host_list:
        print(host)


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
                if string_rec == hash:
                    server_ip = addr[0]
                    print("Server discovered at " + server_ip)
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

def get_current_seconds():
    return int(str(time.time()).split('.')[0])

def print_server_ip():
    global server_ip
    server_ip = server_ip

def retrieve_clients(tcp_port, server_ip):
    #msg = "retrieve"
    p = Packet("retrieve")
    tcp_client(tcp_port, p.get_packet(), server_ip)

def ping_clients(tcp_port):
    #msg = "PING " + own_ip
    logging.info(shared_list)
    p = Packet("ping")
    logging.info('length of shared_list: ' + str(len(shared_list)) + ' ' + str(shared_list))
    if len(shared_list) != 0:
        for ip in shared_list:
            if len(clients_dict) > 0 and ip in clients_dict:
                print('Pinging ' + clients_dict[ip])
            else:
                print('Pinging ' + ip)
            tcp_client(tcp_port, p.get_packet(), ip)

def string_to_dict(string):
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
    # use tcp_port to connect with server, bc server listens on 9995
    # clients are listening on 9000, use tcp_listen to connect with other clients

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
            logging.info("Starting: {}".format(p.name))
            p.start()

    except KeyboardInterrupt:
        for p in procs:
            logging.info("Terminating: {}".format(p.name))
            if p.is_alive():
                p.terminate()
                sleep(0.1)
            if not p.is_alive():
                logging.info(p.join())
    
    i = 0
    while True:
        if i % 2 == 0:
            print('Retrieving current connections from server...')
            retrieve_clients(tcp_port, server_ip)
        if i % 3 == 0:
            if len(shared_list) > 0:
                print('Pinging connected clients...')
                ping_clients(tcp_listen)
            logging.info('shared list in main: ' + str(shared_list))
        sleep(5)
        i = i + 1
    
#######################################
#               Main                  #
#######################################
def main():
    communication_manager()


if __name__ == "__main__":
    main()
