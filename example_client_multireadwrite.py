"""
This is a simple demo for using CoAP for communicating with Exosite.

Author: Patrick Barrett(patrickbarrett@exosite.com)

Note this example requires the cbor library. (pip install cbor)
"""

import socket
import binascii
import coap
import cbor

# Update these parameters with the CIK of the device and the aliases of the
# datasources you'd like to use.
CIK = ""
READ_ALIASES = ("alias r1", "alias r2", )
WRITE_PAIRS = {
	"alias w1": "value w1",
	"alias w2": "value w2",
}

SERVER = "coap.exosite.com"
PORT = 5683

# Create a New Conformable GET CoAP Request with Message ID 0x37.
msg = coap.Message(mtype=coap.CON, mid=0x37, code=coap.POST)

# Set the path where the format is "/1a/<datasource alias>".
msg.opt.uri_path = ('1a',  )

# Encode the CIK to binary to save data
msg.opt.uri_query = (binascii.a2b_hex(CIK), ) + READ_ALIASES

msg.payload = cbor.dumps(WRITE_PAIRS)

print("------------ Send Message ------------")
print(msg)
print(binascii.b2a_hex(msg.payload))

# Setup Socket as UDP
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

# Encode and Send Message
sock.sendto(msg.encode(), (SERVER, PORT))

# Wait for Response
data, addr = sock.recvfrom(2048) # maximum packet size is 1500 bytes

# Decode and Display Response
recv_msg = coap.Message.decode(data)
print("------------ Recv Message ------------")
print(recv_msg)
print("Hex: ", binascii.b2a_hex(recv_msg.payload))
print("Decoded: ", cbor.loads(recv_msg.payload))
