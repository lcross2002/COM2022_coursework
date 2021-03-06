# Imports
from bitarray import bitarray
import socket
import config
import packet
import json
import rsa
import random

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
tested = True

# Socket settings
socket.setdefaulttimeout(5)

# Creates socket [address type, udp]
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Separates the message into components
def separate_message(message):
    sequence = int.from_bytes(message[0:4], byteorder='big')
    flags = bitarray(endian='big')
    flags.frombytes(message[4:6])
    length = int.from_bytes(message[6:8], byteorder='big')
    body = message[8:len(message)]

    return (sequence, flags, length, body)

# Decrypts the message
def decrypt_message(message):
    decrypted_message = rsa.decrypt(message, client_private)
    print(decrypted_message)
    return decrypted_message

def rsa_exchange():
    global server_public
    global client_id_global
    global tested

    if client_id_global == None:
        print('Creating tab')
        print('')

        sequence_check = 0

        # RSA Exchange
        try:
            # RSA Message
            p = packet.packet(False, True, False, sequence_check, None, None, client_public.save_pkcs1(), True)
            print(p.encrypted_raw)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('rsa sent')
            waitingForAck = True

            # ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            waitingForAck = False
            (sequence, flags, length, body) = separate_message(message)
            if flags[0] == 1 and sequence == sequence_check:
                print('correct ack recieved')
                sequence_check += 1
            else:
                print('err')
                rsa_exchange()
                return

            # RSA Recieve
            message, server = client.recvfrom(config.buffer_size)
            (sequence, flags, length, body) = separate_message(message)
            if flags[0] == 1 & flags[1] == 1:
                server_public = rsa.PublicKey.load_pkcs1(body)
                print('rsa recieved ' + str(body))

                # Send empty ACK
                if tested == False:
                    p = packet.packet(True, False, False, sequence_check-1, None, None, None, False)
                    client.sendto(p.encrypted_raw, (config.address, config.port))
                    print('wrong ack sent')
                    tested = True
                else:
                    p = packet.packet(True, False, False, sequence_check, None, None, None, False)
                    client.sendto(p.encrypted_raw, (config.address, config.port))
                    print('ack sent')

                sequence_check += 1

                # Send FIN
                p = packet.packet(True, False, True, sequence_check, None, None, None, False)
                client.sendto(p.encrypted_raw, (config.address, config.port))
                print('fin ack sent')

                # Generic ACK Recieve
                message, server = client.recvfrom(config.buffer_size)
                (sequence, flags, length, body) = separate_message(message)
                if flags[0] == 1:
                    print('generic ack recieved')
                else:
                    print('err')
                    rsa_exchange()
                    return

                sequence_check += 1

                # Final ACK Recieve
                message, server = client.recvfrom(config.buffer_size)
                (sequence, flags, length, body) = separate_message(message)
                if flags[0] == 1 and flags[2] == 1:
                    print('fin ack recieved')
                else:
                    print('err')
                    rsa_exchange()
                    return

                # Send Generic ACK
                p = packet.packet(True, False, False, sequence_check, None, None, None, False)
                client.sendto(p.encrypted_raw, (config.address, config.port))
                print('ack sent')

        except socket.timeout as inst:
            print('timeout!')
            
            if waitingForAck == True:
                print('err no ack recieved ' + str(sequence_check))
            
            rsa_exchange()
            return

        print('rsa exchange completed')

    else:
        print('You already have an existing tab')
        print('Press enter to continue:')
        input()
        print('')

def open_tab():
    global server_public
    global client_id_global

    print('')
    print('Opening tab')

    sequence_check = 0

    try:
        # OPEN Message
        p = packet.packet(False, False, False, sequence_check, None, server_public, "OPEN", False)
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('open sent')

        # ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('ack recieved')
        else:
            print('err wrong ack')

        sequence_check += 1

        # ID Recieve
        message, server = client.recvfrom(config.buffer_size)
        print(message)
        (sequence, flags, length, body) = separate_message(message)
        msg = decrypt_message(body)
        msg = msg.decode('ASCII')
        split = msg.split(' ')
        if split[0] == "SETID":
            client_id_global = int(split[1])
            print('id recieved ' + str(client_id_global))

            # Send empty ACK
            p = packet.packet(True, False, False, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

            sequence_check += 1

            # Send FIN
            p = packet.packet(True, False, True, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('fin ack sent')

            # Generic ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            (sequence, flags, length, body) = separate_message(message)
            if flags[0] == 1:
                print('generic ack recieved')
            else:
                print('err')

            sequence_check += 1

            # Final ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            (sequence, flags, length, body) = separate_message(message)
            if flags[0] == 1 and flags[2] == 1:
                print('fin ack recieved')
            else:
                print('err')

            # Send Generic ACK
            p = packet.packet(True, False, False, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

            print('open tab completed')

    except socket.timeout as inst:
        print('timeout!')
        open_tab()
        return

# Creates a tab
def createTab():
    rsa_exchange()
    open_tab()

def send_drink(choice, quantity):
    global client_id_global
    global tab

    sequence_check = 0

    # Send drink choice
    try:
        # Add drink Message
        msg = "ID " + str(client_id_global) + "\r\nADD " + str(choice) + " " + str(quantity)
        p = packet.packet(False, False, False, 0, None, server_public, msg, False)
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('add drink sent')

        # ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[0] == 1 and sequence == 0:
            print('correct ack recieved')
        else:
            print('err')
            send_drink()
            return

        sequence_check += 1

        # Total Recieve
        message, server = client.recvfrom(config.buffer_size)
        print(message)
        (sequence, flags, length, body) = separate_message(message)
        msg = decrypt_message(body)
        msg = msg.decode('ASCII')
        split = msg.split(' ')
        if split[0] == "TOTAL":
            tab = str(split[1])
            print('total recieved ' + tab)

            # Send empty ACK
            p = packet.packet(True, False, False, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

            sequence_check += 1

            # Send FIN
            p = packet.packet(True, False, True, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('fin ack sent')

            # Generic ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            (sequence, flags, length, body) = separate_message(message)
            if flags[0] == 1:
                print('generic ack recieved')
            else:
                print('err')

            sequence_check += 1

            # Final ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            (sequence, flags, length, body) = separate_message(message)
            if flags[0] == 1 and flags[2] == 1:
                print('fin ack recieved')
            else:
                print('err')

            # Send Generic ACK
            p = packet.packet(True, False, False, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

            print('add to drink completed')

    except socket.timeout as inst:
        print('timeout!')
        send_drink(choice, quantity)
        return

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
        print('[' + str(drink['id']) + '] - ' + drink['name'] + ': ??' + str(drink['price']))

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
    print('')

    send_drink(choice, quantity)

# Views existing tab value
def viewTab():
    print('your current tab value is ??' + str(round(float(tab), 2)))

# Closes a tab
def closeTab():
    global client_id_global
    global server_public
    global tab

    print('closing tab')
    print('')

    sequence_check = 0

    # Closing tab
    try:
        # Close message
        msg = "ID " + str(client_id_global) + "\r\nCLOSE"
        p = packet.packet(False, False, False, sequence_check, None, server_public, msg, False)
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('close tab sent')

        # ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('fin recieved')
            print(body)

            sequence_check += 1

            # Total Recieve
            message, server = client.recvfrom(config.buffer_size)
            (sequence, flags, length, body) = separate_message(message)
            msg = decrypt_message(body)
            msg = msg.decode('ASCII')
            print('total recieved ' + msg)

            # Send empty ACK
            p = packet.packet(True, False, False, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

            sequence_check += 1

        else:
            print('err')
            closeTab()
            return

    except socket.timeout as inst:
        print('timeout!')
        closeTab()
        return

    try:
        # Send FIN
        p = packet.packet(False, False, True, sequence_check, None, None, None, False)
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('fin ack sent')

        # Generic ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('generic ack recieved')
        else:
            print('err')

        sequence_check += 1

        # Final ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[0] == 1 and flags[2] == 1:
            print('fin ack recieved')
        else:
            print('err')

        # Send Generic ACK
        p = packet.packet(True, False, False, sequence_check, None, None, None, False)
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('ack sent')

        # Reset global variables
        client_id_global = None
        tab = 0
        server_public = None

        print('close tab completed')
    except socket.timeout as inst:
        print('timeout!')
        closeTab()
        return

def corrupt_packet():
    try:
        # Corrupt Packet
        #msg = "WAEAWEAWJEAWOE"
        choice = "01"
        quantity = 4
        msg = "ID " + str(client_id_global) + "\r\nADD " + str(choice) + " " + str(quantity)
        p = packet.packet(False, False, False, 7, None, None, msg, False)
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('corrupt packet sent')

        # Generic ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[0] == 1:
            print('generic ack recieved')
        else:
            print('err')

        message, server = client.recvfrom(config.buffer_size)
        print('err, response recieved')

    except socket.timeout as inst:
        print('timeout!')
        print('timeout correctly triggered')

def send_drinks(choices, quantities):
    global client_id_global
    global tab

    sequence_check = 0

    # Send drink choice
    try:
        # Add drink Message
        msg = "ID " + str(client_id_global)

        for i in range(0, len(choices)):
            msg = msg + " ADD " + choices[i] + " " + quantities[i]

        print(msg)
        flags = [True, False, False, False, False, False, False, False, False, False, False, False, False]
        p = packet.packet(False, False, False, sequence_check, flags, server_public, msg, False)
        client.sendto(p.encrypted_raw, (config.address, config.port))
        print('add drink sent')

        # ACK Recieve
        message, server = client.recvfrom(config.buffer_size)
        (sequence, flags, length, body) = separate_message(message)
        if flags[0] == 1 and sequence == 0:
            print('correct ack recieved')
        else:
            print('err')
            send_drinks(choices, quantities)
            return

        sequence_check += 1

        # Total Recieve
        message, server = client.recvfrom(config.buffer_size)
        print(message)
        (sequence, flags, length, body) = separate_message(message)
        msg = decrypt_message(body)
        msg = msg.decode('ASCII')
        split = msg.split(' ')
        if split[0] == "TOTAL":
            tab = str(split[1])
            print('total recieved ' + tab)

            # Send empty ACK
            p = packet.packet(True, False, False, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

            sequence_check += 1

            # Send FIN
            p = packet.packet(True, False, True, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('fin ack sent')

            # Generic ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            (sequence, flags, length, body) = separate_message(message)
            if flags[0] == 1:
                print('generic ack recieved')
            else:
                print('err')

            sequence_check += 1

            # Final ACK Recieve
            message, server = client.recvfrom(config.buffer_size)
            (sequence, flags, length, body) = separate_message(message)
            if flags[0] == 1 and flags[2] == 1:
                print('fin ack recieved')
            else:
                print('err')

            # Send Generic ACK
            p = packet.packet(True, False, False, sequence_check, None, None, None, False)
            client.sendto(p.encrypted_raw, (config.address, config.port))
            print('ack sent')

            print('add to drink completed')

    except socket.timeout as inst:
        print('timeout!')
        send_drinks(choices, quantities)
        return

def add_multiple_to_tab():
    done = False
    choices = []
    quantities = []

    while done == False:
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
            print('[' + str(drink['id']) + '] - ' + drink['name'] + ': ??' + str(drink['price']))

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
        print('')

        choices.append(choice)
        quantities.append(quantity)

        print('Are you finished ordering?')
        print('[1] - Yes')
        print('')
        x = input()

        if x == '1':
            done = True
        
    send_drinks(choices, quantities)

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
    print('[6] - Send corrupt packet')
    print('[7] - Add multiple drinks to tab')
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
    elif user_input == '6':
        corrupt_packet()
    elif user_input == '7':
        add_multiple_to_tab()
    else:
        print('')
        print('This is not a valid command!')
        print('Press enter to continue:')
        input()
        print('')