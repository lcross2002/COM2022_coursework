# Imports
from bitarray import bitarray
import socket
import config
import packet
import secrets

# Global variables
codes = dict()

# Creates socket [address type, udp]
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Binds socket [ip, port]
server.bind(('', config.port))

# Creates a unique auth code
def createAuthCode():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(10))

#
while True:
    # Retrieve
    message, address = server.recvfrom(config.buffer_size)

    print(message)
    print('')

    length = int.from_bytes(message[0:4], byteorder='big')
    print('length (bytes): ' + str(length))
    print('')

    checksum = int.from_bytes(message[5:8], byteorder='big')
    print('checksum bytes:' + str(checksum))
    print('')

    print('bit flags:')
    flags = bitarray(endian='big')
    flags.frombytes(message[8:10])
    print(flags)
    print('')

    id = int.from_bytes(message[9:12], byteorder='big')
    print('id bytes:' + str(id))
    print('')

    print('message bytes:')
    print(message[12])
    print(message[13])
    print(message[14])
    print(message[15])
    print(str(message[12:16]))
    print('')

    # TODO: Send response
    #server.sendto(message, address)
