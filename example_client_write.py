"""
This is a simple demo for using CoAP for communicating with Exosite.

Author: Patrick Barrett(patrickbarrett@exosite.com)
"""

import socket
import binascii
import coap

# Update these parameters with the CIK of the deice and the alias of the
# datasource of what you'd like to read.
CIK = ""
ALIAS = ""

SERVER = "coap.exosite.com"
PORT = 5683

# Create a New Conformable GET CoAP Request with Message ID 0x37.
msg = coap.Message(mtype=coap.CON, mid=0x37, code=coap.POST)

# Set the path where the format is "/1a/<datasource alias>".
msg.opt.uri_path = ('1a', ALIAS,)

# Encode the CIK to binary to save data
msg.opt.uri_query = (binascii.a2b_hex(CIK),)

msg.payload = "37"

print("Sending Message: {}".format(binascii.b2a_hex(msg.encode())))
print(coap.humanFormatMessage(msg))

# Setup Socket as UDP
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

# Encode and Send Message
sock.sendto(msg.encode(), (SERVER, PORT))

# Wait for Response
data, addr = sock.recvfrom(2048) # maximum packet size is 1500 bytes

# Decode and Display Response
recv_msg = coap.Message.decode(data)
print("Received Message: {}".format(binascii.b2a_hex(data)))
print(coap.humanFormatMessage(recv_msg))