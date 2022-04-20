# Imports
from bitarray import bitarray
import socket
import config
import packet
import mapping
import rsa

# RSA
(server_public, server_private) = rsa.newkeys(512)

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
        p = packet.packet(True, True, False, 0, None, None, str(server_public.n))
        packet_bytes = p.encrypted_raw
        server.sendto(packet_bytes, address)
        print('rsa sent')

        # ACK Recieve
        message, address = server.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')

    except socket.timeout as inst:
        # TODO: Timeout
        print('timeout!')
        input()

# Creates a unique auth code
def createAuthCode():
    found = False

    # TODO: fix
    prev = -1
    for k, v in ids.items():
        if (k - prev) != 1:
            x = k
            found = True
            break
        else:
            prev = k

    if found == False:
        if len(ids.items()) == 1:
            x = 1
        else:
            x = len(ids.items())

    if x > max_ids:
        print('the maximum number of tabs has been created')
    else:
        ids[x] = 0
        print('created new tab with id: ' + x)
    
    return x

# Decrypts the message
def decrypt_message(message):
    message = rsa.decrypt(messsage, server_private)
    message = message.decode('ASCII')
    return decrypted_message

# Separates the message into components
def separate_message(message):
    client_id = int.from_bytes(message[0:4], byteorder='big')
    flags = bitarray(endian='big')
    flags.frombytes(message[4:6])
    length = int.from_bytes(message[6:8], byteorder='big')
    body = message[8:length]

    return (client_id, flags, length, body)

# Processes the message
def process_message(client_id, flags, length, body, address):
    global clients
    
    # RSA Exchange
    if flags[1] == 1:

        # First sets the client key in mapping
        for c in clients:
            if c.address == address:
                c.client_public = body
                break

        # Then sends public key
        send_public_key(address)

    return 0

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