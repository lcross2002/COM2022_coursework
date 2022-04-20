# Imports
from bitarray import bitarray
import rsa

# Packet class
class packet:
    # Constructor
    def __init__(self, ack, rsa, fin, client_id, flags, key, body):
        # Fields
        self.raw = None
        self.encrypted_raw = None
        self.ack = ack
        self.rsa = rsa
        self.fin = fin
        self.flags = flags
        self.key = key
        self.length = 0
        self.id = client_id
        self.body = body

        # Processes the packet once fields are initalised
        self.process_packet()

    # Processes the packet
    def process_packet(self):
        # Calculate length
        self.calculate_length()

        # Convert to bytes
        self.convert_to_bytes()

        # Encrypt the packet
        self.encrypt_packet()

    # Calculates length
    def calculate_length(self):
        if self.body != None:
            self.length = 8 + len(bytes(self.body, 'ASCII'))
        else:
            self.length = 8

    # Converts the packet to bytes
    def convert_to_bytes(self):
        id_bytes = self.id.to_bytes(4, byteorder='big')
        total = id_bytes

        total_flags = bitarray()

        # ACK
        if self.ack:
            total_flags.append(1)
        else:
            total_flags.append(0)

        # RSA
        if self.rsa:
            total_flags.append(1)
        else:
            total_flags.append(0)

        # FIN
        if self.fin:
            total_flags.append(1)
        else:
            total_flags.append(0)

        # Flags
        if self.flags != None:
            for flag in self.flags:
                if flag:
                    total_flags.append(1)
                else:
                    total_flags.append(0)
        else:
            total_flags.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        # Convert the bitarray to bytes
        flag_bytes = total_flags.tobytes()
        total = total + flag_bytes

        # Convert length to bytes
        length_bytes = self.length.to_bytes(2, byteorder='big')
        total = total + length_bytes

        # Convert body to bytes
        if self.body != None:
            body_bytes = bytes(self.body, 'ASCII')
            total = total + body_bytes

        # Set the field to the total
        self.raw = total

    # Encrypts the packet
    def encrypt_packet(self):
        # TODO
        if self.key == None:
            self.encrypted_raw = self.raw
        else:
            print('encrypting message')
            self.encrypted_raw = rsa.encrypt(self.raw, self.key)