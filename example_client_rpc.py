"""
A more complicated demo of using the RPC proxy to access Exosite's JSON RPC API
using CoAP and CBOR.

To use this example you will need to make sure you have run:

  pip install cbor

Author: Patrick Barrett(patrickbarrett@exosite.com)
"""

import socket
import binascii
import coap
import cbor

# Update these parameters with the CIK of the deice and the alias of the
# datasource that you'd like to read.
CIK = ""
ALIAS = ""

SERVER = "coap.exosite.com"
PORT = 5683


# This is in the standard format for the RPC API, see
# http://docs.exosite.com/rpc
read_call = {
	"procedure": "read",
	"arguments": [
		{"alias": ALIAS},
		{"limit": 1}
	],
	"id": 1
}

request = {
	"auth" : {
		"cik": CIK
	},
	"calls": [ read_call ]
}

# Create a New Conformable GET CoAP Request with Message ID 0x37.
msg = coap.Message(mtype=coap.CON, mid=0x37, code=coap.POST)

# Set the path where the format is "/rpc/".
msg.opt.uri_path = ('rpc',  )

# Add Content Format Option
msg.opt.content_format = 60 #application/cbor

# Encode Request as CBOR and Put in Payload
msg.payload = cbor.dumps(request)

print(request)

print("------------ Send Message ------------")
print(msg)

# Setup Socket as UDP
sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP

# Encode and Send Message
sock.sendto(msg.encode(), (SERVER, PORT))

body = b""

while True:
	# Wait for Response
	data, addr = sock.recvfrom(2048) # maximum packet size is 1500 bytes

	# Decode and Display Response
	recv_msg = coap.Message.decode(data)
	print("------------ Recv Message ------------")
	print(recv_msg)
	body += recv_msg.payload

	# Only Continue Requests if Sever Says There's More
	if recv_msg.opt.block2 == None or recv_msg.opt.block2[1] == 0:
		break

	# Update Request to Ask for Next Block
	msg.opt.block2 = (recv_msg.opt.block2[0] + 1, 0, recv_msg.opt.block2[2])

	# Encode and Send Message
	sock.sendto(msg.encode(), (SERVER, PORT))

# Decode CBOR Response to Python Object
response = cbor.loads(body)

# Print the RPC Response in JSON-like Format
print("RPC Response:")
print(response)

# Print Just the Value of the dataport
print("Dataport Value:")
print(response[0]['result'][0][1])
