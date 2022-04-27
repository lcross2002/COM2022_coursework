# Imports
from bitarray import bitarray
import socket
import config
import packet
import mapping
import rsa
import json
import random

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
    server.settimeout(1)

    sequence_check = 1

    # RSA Exchange
    try:
        # RSA Message
        p = packet.packet(True, True, False, sequence_check, None, None, server_public.save_pkcs1(), True)
        server.sendto(p.encrypted_raw, address)
        print('rsa sent')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')
            send_public_key(address)
            return

        sequence_check += 1

        # ACK FIN Recieve
        message, address = server.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[2] == 1:
            print('ack fin recieved')
        else:
            print('err')
            send_public_key(address)
            return

        # Send Generic ACK
        p = packet.packet(True, False, False, sequence_check, None, None, None, False)
        server.sendto(p.encrypted_raw, address)
        print('sent generic ack')

        sequence_check += 1

        # Send Fin ACK
        p = packet.packet(True, False, True, sequence_check, None, None, None, False)
        server.sendto(p.encrypted_raw, address)
        print('sent fin ack')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')
            send_public_key(address)
            return

        print('rsa exchange completed')
        print('')

    except socket.timeout as inst:
        print('timeout!')
        send_public_key(address)

    server.settimeout(None)

def send_id(client):
    server.settimeout(1)

    sequence_check = 1

    # Send ID
    try:
        # ID Message
        msg = "SETID " + str(client.client_id)
        p = packet.packet(False, False, False, sequence_check, None, client.client_public, msg, False)
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
            send_id(address)
            return

        sequence_check += 1

        # ACK FIN Recieve
        message, address = server.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[2] == 1:
            print('ack fin recieved')
        else:
            print('err')
            send_id(address)
            return

        # Send Generic ACK
        p = packet.packet(True, False, False, sequence_check, None, None, None, False)
        server.sendto(p.encrypted_raw, address)
        print('sent generic ack')

        sequence_check += 1

        # Send Fin ACK
        p = packet.packet(True, False, True, sequence_check, None, None, None, False)
        server.sendto(p.encrypted_raw, address)
        print('sent fin ack')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')
            send_id(address)
            return

        print('id exchange completed')
        print('')

    except socket.timeout as inst:
        print('timeout!')
        send_id(client)

    server.settimeout(None)

# Creates a unique ID code
def create_id_code():
    
    if len(clients) == max_clients:
        print('there is already the maximum number of clients')
        return

    if len(clients) == 0:
        return 1

    x = random.randint(1, max_clients)

    arr = []
    for c in clients:
        arr.append(c.client_id)

    dupe = False

    if x in arr:
        dupe = True

    while dupe == True:
        x = random.randint(1, max_clients)
        if x in arr:
            dupe = True
        else:
            dupe = False

    return x

def send_add_to_tab(client, total):
    server.settimeout(1)

    sequence_check = 1

    # Total Message
    try:
        # Total Message
        msg = "TOTAL " + str(c.total)
        p = packet.packet(False, False, False, sequence_check, None, c.client_public, msg, False)
        server.sendto(p.encrypted_raw, client.address)
        print('total sent')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')
            send_public_key(address)
            return

        sequence_check += 1

        # ACK FIN Recieve
        message, address = server.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[2] == 1:
            print('ack fin recieved')
        else:
            print('err')
            send_public_key(address)
            return

        # Send Generic ACK
        p = packet.packet(True, False, False, sequence_check, None, None, None, False)
        server.sendto(p.encrypted_raw, address)
        print('sent generic ack')

        sequence_check += 1

        # Send Fin ACK
        p = packet.packet(True, False, True, sequence_check, None, None, None, False)
        server.sendto(p.encrypted_raw, address)
        print('sent fin ack')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')
            send_public_key(address)
            return

        print('add to drink completed')
        print('')
    
    except socket.timeout as inst:
        print('timeout!')
        send_add_to_tab(client, total)
        return

    server.settimeout(None)

def add_to_tab(client, split):
    global clients
    
    drink = split[3]
    quantity = int(split[4])

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
            send_add_to_tab(c, (c.total + total))
            c.total = c.total + total

def close_tab(client):
    server.settimeout(1)

    global clients
    
    sequence_check = 1

    # Close tab
    try:
        # Fin Message
        msg = "TOTAL " + str(client.total)
        p = packet.packet(True, False, False, sequence_check, None, client.client_public, msg, False)
        server.sendto(p.encrypted_raw, client.address)
        print('total sent')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')
            send_public_key(address)
            return

        sequence_check += 1

        # ACK FIN Recieve
        message, address = server.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[2] == 1:
            print('ack fin recieved')
        else:
            print('err')
            send_public_key(address)
            return

        # Send Generic ACK
        p = packet.packet(True, False, False, sequence_check, None, None, None, False)
        server.sendto(p.encrypted_raw, address)
        print('sent generic ack')

        sequence_check += 1

        # Send Fin ACK
        p = packet.packet(True, False, True, sequence_check, None, None, None, False)
        server.sendto(p.encrypted_raw, address)
        print('sent fin ack')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')
            send_public_key(address)
            return

        # Remove from list
        for c in clients:
            if c.address == client.address:
                clients.remove(c)
                break

        print('client close completed')
        print('')

    except socket.timeout as inst:
        print('timeout!')
        close_tab(client)

    server.settimeout(None)

# Decrypts the message
def decrypt_message(body):
    decrypted_message = rsa.decrypt(body, server_private)
    print(decrypted_message)
    return decrypted_message

# Separates the message into components
def separate_message(message):
    sequence = int.from_bytes(message[0:4], byteorder='big')
    flags = bitarray(endian='big')
    flags.frombytes(message[4:6])
    length = int.from_bytes(message[6:8], byteorder='big')
    body = message[8:len(message)]

    return (sequence, flags, length, body)

# Processes the message
def process_message(sequence, flags, length, body, address):
    global clients

    body = body.decode('ASCII')
    split = body.split(' ')
    
    # RSA Exchange
    if flags[1] == 1:

        # First sets the client key in mapping
        for c in clients:
            if c.address == address:
                c.client_public = rsa.PublicKey.load_pkcs1(body)
                break

        # Then sends public key
        send_public_key(address)
    
    # OPEN Tab
    elif split[0] == "OPEN":
        # Creates ID
        new_id = create_id_code()
        
        # Applys ID
        for c in clients:
            if c.address == address:
                c.client_id = new_id
                send_id(c)
                break

    # CLOSE Tab
    elif split[0] == "CLOSE":
        client = None
        
        # Finds client
        for c in clients:
            if c.address == address:
                client = c
                break

        close_tab(client)

    # ADD to tab
    elif split[2] == "ADD":
        client = None
        
        # Finds client
        for c in clients:
            if c.address == address:
                client = c
                break

        add_to_tab(client, split)

#
while True:
    # Retrieve
    message, address = server.recvfrom(config.buffer_size)
    print('recieved message')
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

    # Seperates the message
    (sequence, flags, length, body) = separate_message(message)

    # If address does not exist no need to decrypt message
    if found == True:
        decrypted_message = decrypt_message(body)
    else:
        c = mapping.mapping(0, address, None, 0)
        clients.append(c)
        decrypted_message = body

    # Send empty generic ACK
    p = packet.packet(True, False, False, sequence, None, None, None, False)
    server.sendto(p.encrypted_raw, address)
    print('sent generic ack')

    # Proceses the message
    process_message(sequence, flags, length, decrypted_message, address)