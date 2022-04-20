# Imports
from bitarray import bitarray
import socket
import config
import packet
import json
import rsa

# Loading JSON
f = open('drinks.json')
data = json.load(f)
f.close()

# RSA
(client_public, client_private) = rsa.newkeys(512, accurate=True)

# Global variables
client_id_global = None
tab = 0
server_public = None

# Socket settings
socket.setdefaulttimeout(1)

# Creates socket [address type, udp]
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Separates the message into components
def separate_message(message):
    client_id = int.from_bytes(message[0:4], byteorder='big')
    flags = bitarray(endian='big')
    flags.frombytes(message[4:6])
    length = int.from_bytes(message[6:8], byteorder='big')
    body = message[8:length]
    body = body.decode('ASCII')

    return (client_id, flags, length, body)

# Decrypts the message
def decrypt_message(message):
    decrypted_message = rsa.decrypt(message, client_private)
    print(decrypted_message)
    return decrypted_message

# Creates a tab
def createTab():
    global server_public
    global client_id_global

    if client_id_global == None:
        print('Creating tab')
        print('')

        # RSA Exchange
        try:
            # RSA Message
            p = packet.packet(False, True, False, 0, None, None, str(client_public))
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('rsa sent')

            # ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            (client_id, flags, length, body) = separate_message(message)
            if flags[0] == 1:
                print('ack recieved')
            else:
                print('err')

            # RSA Recieve
            message, server = client.recvfrom(config.buffer_size)
            (client_id, flags, length, body) = separate_message(message)
            if flags[0] == 1 & flags[1] == 1:
                server_public = rsa.PublicKey(int(body[10:164]), int(body[166:171]))
                print('rsa recieved ' + body)

                # Send empty ACK
                p = packet.packet(True, False, False, 0, None, None, None)
                client.sendto(p.encrypted_raw, (config.address, config.port))
                print('ack sent')

        except socket.timeout as inst:
            # TODO: Timeout
            print('timeout!')
            input()
            return

        print('')

        try:
            # OPEN Message
            p = packet.packet(False, False, False, 0, None, server_public, "OPEN")
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('open sent')

            # ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            (client_id, flags, length, body) = separate_message(message)
            if flags[0] == 1:
                print('ack recieved')
            else:
                print('err')

            # ID Recieve
            message, server = client.recvfrom(config.buffer_size)
            print(message)
            message = decrypt_message(message)
            (client_id, flags, length, body) = separate_message(message)
            split = body.split(' ')
            if split[0] == "SETID":
                client_id_global = int(split[1])
                print('id recieved ' + str(client_id_global))

                # Send empty ACK
                p = packet.packet(True, False, False, 0, None, None, None)
                client.sendto(p.encrypted_raw, (config.address, config.port))
                print('ack sent')

        except socket.timeout as inst:
            # TODO: Timeout
            print('timeout!')
            input()
            return

    else:
        print('You already have an existing tab')
        input()
        print('')

# Adds to an existing tab
def addToTab():
    global tab

    if client_id_global == None:
        print('You do not have a tab to add to!')
        print('Press enter to continue:')
        input()
        print('')
        return

    # Get user drink choice
    drinks = data['drinks']

    print('drinks:')
    for drink in drinks:
        print('[' + str(drink['id']) + '] - ' + drink['name'] + ': £' + str(drink['price']))

    print('')
    print('Enter a value from inside the brackets:')
    choice = input()

    found = False
    for drink in drinks:
        if drink['id'] == choice:
            found = True
            break

    if found == False:
        print('this drink does not exist')
        print('')
        return

    print('')
    print('Enter the quantity:')
    quantity = input()

    # Send drink choice
    try:
        # Add drink Message
        msg = "ADD " + str(choice) + " " + str(quantity)
        p = packet.packet(False, False, False, client_id_global, None, server_public, msg)
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('add drink sent')

        # ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')

        # Total Recieve
        message, server = client.recvfrom(config.buffer_size)
        print(message)
        message = decrypt_message(message)
        (client_id, flags, length, body) = separate_message(message)
        split = body.split(' ')
        if split[0] == "TOTAL":
            tab = float(split[1])
            print('total recieved ' + str(tab))

            # Send empty ACK
            p = packet.packet(True, False, False, 0, None, None, None)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

    except socket.timeout as inst:
        # TODO: Timeout
        print('timeout!')
        input()
        return

# Views existing tab value
def viewTab():
    print('your current tab value is ' + str(tab))

# Closes a tab
def closeTab():
    global client_id_global
    global server_public

    print('closing tab')
    print('')

    # Closing tab
    try:
        # Close message
        p = packet.packet(False, False, False, client_id_global, None, server_public, 'CLOSE')
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('close tab sent')

        # ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err')

        # Fin Recieve
        message, server = client.recvfrom(config.buffer_size)
        message = decrypt_message(message)
        (client_id, flags, length, body) = separate_message(message)
        if flags[0] == 0 and flags[2] == 1:
            print('fin recieved')
            print(body)

            # Send empty ACK
            p = packet.packet(True, False, True, 0, None, None, None)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

            # Reset global variables
            client_id_global = None
            tab = 0
            server_public = None

        else:
            print('err')

    except socket.timeout as inst:
        # TODO: Timeout
        print('timeout!')
        input()
        return

# 
while True:
    # Resets variable
    user_input = None

    print('')
    print('Welcome to The Client of the Bar Tab Protocol (BTP)')
    print('')
    print('Commands:')
    print('')
    print('[1] - Create a tab')
    print('[2] - Add to a tab')
    print('[3] - View tab')
    print('[4] - Close a tab')
    print('[5] - Exit')
    print('')
    print('Enter a value from inside the brackets:')

    user_input = input()

    print('')

    if user_input == '1':
        createTab()
    elif user_input == '2':
        addToTab()
    elif user_input == '3':
        viewTab()
    elif user_input == '4':
        closeTab()
    elif user_input == '5':
        quit()
    else:
        print('')
        print('This is not a valid command!')
        print('Press enter to continue:')
        input()
        print('')