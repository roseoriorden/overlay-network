#!/usr/bin/env python3
import ssl
import socket
from time import sleep
import time
from multiprocessing import Process
from socketserver import BaseRequestHandler, TCPServer
import hashlib
import json
import logging

#logging.basicConfig(stream=sys.stdout, level=logging.INFO)

own_ip = None
server_ip = None
connected_clients = {}
client_num = 1
last_connected = {}

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
        global connected_clients
        self.data = self.request.recv(1024).strip()
        client_name = client_register(self)
        ip = self.client_address[0]
        logging.info("Echoing message from: " + client_name + " "  + ip)
        logging.info(self.data)
        self.request.sendall("ACK from server".encode())
        # deal with dictionary
        last_connected[ip] = get_current_seconds()
        delete = []
        for ip in connected_clients:
            client_name = connected_clients[ip]
            if last_connected[ip] < get_current_seconds() - 16:
                #del connected_clients[ip]
                delete.append(ip)
                print('Client ' + client_name + ' has disconnected. Removing...')
                logging.info('deleting client ' + client_name)
        for i in delete:
            del connected_clients[i]
            del last_connected[i]
        logging.info('current connections: ' + str(last_connected))
        # decode message
        # convert bytes to string
        b_to_s = self.data.decode('utf-8')
        logging.info("after decode: " + b_to_s + str(type(b_to_s)))
        # convert string to json object/dict
        rec = json.loads(self.data.decode('utf-8'))
        #print(rec + str(type(rec)))
        if rec['type'] == 'retrieve':#self.data == b'retrieve':
            logging.info('received retrieve from ' + ip)
            print('Received retrieve clients request from ' + connected_clients[ip] +
                    '\nResponding with list of connected clients...')
            for client in connected_clients.values():
                print(client)
            p = Packet("connected", json.dumps(connected_clients))
            #print('dumps ' + str(json.dumps(connected_clients)))
            packet = p.get_packet()
            tcp_client(9990, packet, ip)
        if self.data == b'ping':
            logging.info('received ping')
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

def client_register(self):
    # add new client to dictionary of clients
    # connected_clients = { IP : host_name }
    #count = len(connected_clients) + 1
    global client_num
    ip = self.client_address[0]
    if ip in connected_clients.keys():
        return connected_clients[ip]
    client_name = "client" + str(client_num) + ".c6610.uml.edu"
    connected_clients[ip] = client_name
    client_num = client_num + 1
    print('A new client has connected: ' + client_name)
    return client_name

def check_connected_clients():
    # check which clients connect with server for the check
    pass


def tcp_client(port, data, server_ip):
    # Initialize a TCP client socket using SOCK_STREAM
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cntx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cntx.load_verify_locations('cert.pem')
    cntx.load_cert_chain('cert.pem')

    s = cntx.wrap_socket(s, server_hostname='test.server')
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

#######################################
#          Broadcast Example          #
#######################################
def broadcast_sender(port):
    count = 0
    hash = get_bcast_hash()
    print("Broadcasting to the network...")
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

def get_current_seconds():
    return int(str(time.time()).split('.')[0])

def print_server_ip():
    global server_ip
    server_ip = server_ip
    logging.info("sever IP in helper func: " + str(server_ip))

######################################
#              Message               #
######################################
class Packet:
    def __init__(self, p_type, msg):
        p_contents = { "type" : p_type,
                        "msg" : msg }
        self.packet = json.dumps(p_contents)
    def get_packet(self):
        return self.packet
    def get_type(self):
        p_type = json.loads(self.get_packet())['type']
        return p_type
    def get_msg(self):
        msg = json.loads(self.get_packet())['msg']
        return msg


#######################################
#               Driver                #
#######################################
def communication_manager():
    global server_ip
    # find own ip
    init_ip()

    bcast_port = 1337
    tcp_listen = 9995

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


#######################################
#               Main                  #
#######################################
def main():
    communication_manager()


if __name__ == "__main__":
    main()
