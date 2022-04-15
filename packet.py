# Imports
from bitarray import bitarray

# Packet class
class packet:
    # Constructor
    def __init__(self, ack, nack, rsa, flags, id, body):
        self.raw = None
        self.encrypted_raw = None
        self.length = 0
        self.checksum = 0
        self.ack = ack
        self.nack = nack
        self.rsa = rsa
        self.flags = flags
        self.id = id
        self.body = body

        # Processes the packet once fields are initalised
        self.process_packet()

    # Processes the packet
    def process_packet(self):
        # Calculate length
        self.calculate_length()

        # Calculate checksum
        self.calculate_checksum()

        # Convert to bytes
        self.convert_to_bytes()

        # Encrypt the packet
        self.encrypt_packet()

    # Calculates length
    def calculate_length(self):
        self.length = 12 + len(bytes(self.body, 'ASCII'))

    # Calculates checksum
    def calculate_checksum(self):
        # TODO
        return 0

    # Converts the packet to bytes
    def convert_to_bytes(self):
        # Convert length to bytes
        length_bytes = self.length.to_bytes(4, byteorder='big')

        # Convert the checksum to bytes
        checksum_bytes = self.checksum.to_bytes(4, byteorder='big')

        # Convert flags to bytes
        total_flags = bitarray()

        # ACK
        if self.ack:
            total_flags.append(1)
        else:
            total_flags.append(0)

        # NACK
        if self.nack:
            total_flags.append(1)
        else:
            total_flags.append(0)

        # RSA
        if self.rsa:
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

        # Convert id to bytes
        id_bytes = self.id.to_bytes(2, byteorder='big')

        # Convert body to bytes
        body_bytes = bytes(self.body, 'ASCII')

        # Combine them
        total = length_bytes + checksum_bytes + flag_bytes + id_bytes + body_bytes

        # Set the field to the total
        self.raw = total

    # Encrypts the packet
    def encrypt_packet(self):
        # TODO
        self.encrypted_raw = self.raw
