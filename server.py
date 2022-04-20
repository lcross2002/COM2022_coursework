# Imports
from bitarray import bitarray
import socket
import config
import packet
import mapping
import rsa
import json

# Loading JSON
f = open('drinks.json')
data = json.load(f)
f.close()

# RSA
(server_public, server_private) = rsa.newkeys(512, accurate=True)

# Global variables
clients = []
max_clients = 11

# Creates socket [address type, udp]
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Binds socket [ip, port]
server.bind(('', config.port))

def send_public_key(address):
    # RSA Exchange
    try:
        # RSA Message
        p = packet.packet(True, True, False, 0, None, None, str(server_public))
        server.sendto(p.encrypted_raw, address)
        print('rsa sent')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')

    except socket.timeout as inst:
        print('timeout!')
        send_public_key(address)

def send_id(client):
    # Send ID
    try:
        # ID Message
        msg = "SETID " + str(client.client_id)
        p = packet.packet(False, False, False, 0, None, client.client_public, msg)
        packet_bytes = p.encrypted_raw
        server.sendto(packet_bytes, client.address)
        print('ID sent')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')

    except socket.timeout as inst:
        print('timeout!')
        send_id(client)

# Creates a unique ID code
def create_id_code():
    
    if len(clients) == max_clients:
        print('there is already the maximum number of clients')
        return

    if len(clients) == 0:
        return 1

    # Algorithm which finds the lowest available ID number
    found = False
    new_id = -1
    prev = 0
    for c in clients:
        if c.client_id != 0:
            if (c.client_id - prev) != 1:
                new_id = c.client_id
                found = True
                break
            else:
                prev = c.client_id

    if found == False:
        new_id = len(clients)

    if new_id == -1:
        print('cannot find id')
    else:
        return new_id

def add_to_tab(client, body):
    global clients

    split = body.split(' ')
    drink = split[1]
    quantity = int(split[2])

    price = -1
    drinks = data['drinks']
    for d in drinks:
        if d['id'] == drink:
            price = d['price']
            break

    if price == -1:
        print('could not find drink with that id')
        return

    total = price * quantity

    for c in clients:
        if c.client_id == client.client_id:
            c.total = c.total + total

            # Total Message
            try:
                # Total Message
                msg = "TOTAL " + str(c.total)
                p = packet.packet(False, False, False, c.client_id, None, c.client_public, msg)
                server.sendto(p.encrypted_raw, client.address)
                print('total sent')

                # ACK Recieve
                message, address = server.recvfrom(config.buffer_size)
                (client_id, flags, length, body) = separate_message(message)
                if flags[0] == 1:
                    print('ack recieved')
                else:
                    print('err')
            
            except socket.timeout as inst:
                print('timeout!')
                add_to_tab(client, body)

            break

def close_tab(client):
    global clients
    
    # Close tab
    try:
        # Fin Message
        msg = "TOTAL " + str(client.total)
        p = packet.packet(False, False, True, client.client_id, None, client.client_public, msg)
        server.sendto(p.encrypted_raw, client.address)
        print('fin total sent')

        # ACK FIN Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1 and flags[2] == 1:
            print('ack fin recieved')
        else:
            print('err')

        # Remove from list
        for c in clients:
            if c.address == client.address:
                clients.remove(c)
                break

    except socket.timeout as inst:
        print('timeout!')
        close_tab(client)
    
    return 0

# Decrypts the message
def decrypt_message(message):
    decrypted_message = rsa.decrypt(message, server_private)
    print(decrypted_message)
    return decrypted_message

# Separates the message into components
def separate_message(message):
    client_id = int.from_bytes(message[0:4], byteorder='big')
    flags = bitarray(endian='big')
    flags.frombytes(message[4:6])
    length = int.from_bytes(message[6:8], byteorder='big')
    body = message[8:length]
    body = body.decode('ASCII')

    return (client_id, flags, length, body)

# Processes the message
def process_message(client_id, flags, length, body, address):
    global clients
    
    # RSA Exchange
    if flags[1] == 1:

        # First sets the client key in mapping
        for c in clients:
            if c.address == address:
                print(body[10:164])
                print(body[166:171])
                c.client_public = rsa.PublicKey(int(body[10:164]), int(body[166:171]))
                break

        # Then sends public key
        send_public_key(address)
    
    # OPEN Tab
    elif body == "OPEN":
        # Creates ID
        new_id = create_id_code()

        client = None
        # Applys ID
        for c in clients:
            if c.address == address:
                c.client_id = new_id
                client = c
                break

        send_id(client)

    # ADD to tab
    elif body[0:3] == "ADD":
        client = None
        
        # Finds client
        for c in clients:
            if c.address == address:
                client = c
                break

        add_to_tab(client, body)

    elif body[0:5] == "CLOSE":
        client = None
        
        # Finds client
        for c in clients:
            if c.address == address:
                client = c
                break

        close_tab(client)

#
while True:
    # Retrieve
    message, address = server.recvfrom(config.buffer_size)
    print('recieved message')

    # Send empty ACK
    p = packet.packet(True, False, False, 0, None, None, None)
    server.sendto(p.encrypted_raw, address)
    print('sent ack')

    print(message)
    print('')

    # Checks if the client already exists
    found = False
    found_client = None
    if clients != None:
        for c in clients:
            if c.address == address:
                found = True
                found_client = c
                break

    # If address does not exist no need to decrypt message
    if found == True:
        decrypted_message = decrypt_message(message)
    else:
        c = mapping.mapping(0, address, None, 0)
        clients.append(c)
        decrypted_message = message

    # Seperates the message
    (client_id, flags, length, body) = separate_message(decrypted_message)

    # Proceses the message
    process_message(client_id, flags, length, body, address)