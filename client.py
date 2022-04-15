# Imports
import socket
import config
import packet
import json

# Loading JSON
f = open('drinks.json')
data = json.load(f)
f.close()

# Global variables
auth_code = None
tab = 0

# Socket settings
socket.setdefaulttimeout(1)

# Creates socket [address type, udp]
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Creates a tab
def createTab():
    if auth_code == None:
        print('Creating tab')
        try:
            p = packet.packet(True, False, False, None, 12, 'OPEN')
            packet_bytes = p.encrypted_raw
            client.sendto(packet_bytes, (config.address, config.port))

            data, server = client.recvfrom(config.buffer_size)            

        except socket.timeout as inst:
            print('timeout!')

    else:
        print('You already have an existing tab')

# Adds to an existing tab
def addToTab():
    print('')

    # Only works if there is an auth code
    if auth_code == None:
        print('You have not set up a tab')
        print('')
    else:
        # Outputs available drinks
        print('drinks:')
        for drink in data['drinks']:
            print('[' + drink['id'] + '] - ' + drink['name'] + ': ' + str(drink['price']))
        
        print()
        print('Enter a value from inside the brackets:')

        drink_choice = input()

# Views existing tab value
def viewTab():
    print('your current tab value is ' + str(tab))

# Closes a tab
def closeTab():
    return 0

# 
while True:
    # Resets global variable
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
