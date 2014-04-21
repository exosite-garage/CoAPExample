"""
COAP Message Encoding and Decoding

Based (almost entirely) on txThings library by Maciej Wasilak.
https://github.com/siskin/txThings

Modifications by Patrick Barrett(patrickbarrett@exosite.com) are copyright 2014
Exosite, LLC and are released in the MIT License.
"""

import random
import copy
import struct
import collections
from itertools import chain


COAP_PORT = 5683
"""The IANA-assigned standard port for COAP services."""

#   +-------------------+---------------+
#   | name              | default value |
#   +-------------------+---------------+
#   | ACK_TIMEOUT       | 2 seconds     |
#   | ACK_RANDOM_FACTOR | 1.5           |
#   | MAX_RETRANSMIT    | 4             |
#   | NSTART            | 1             |
#   | DEFAULT_LEISURE   | 5 seconds     |
#   | PROBING_RATE      | 1 Byte/second |
#   +-------------------+---------------+

ACK_TIMEOUT = 2.0
"""The time, in seconds, to wait for an acknowledgement of a
confirmable message. The inter-transmission time doubles
for each retransmission."""

ACK_RANDOM_FACTOR = 1.5
"""Timeout multiplier for anti-synchronization."""

MAX_RETRANSMIT = 4
"""The number of retransmissions of confirmable messages to
non-multicast endpoints before the infrastructure assumes no
acknowledgement will be received."""

NSTART = 1
"""Maximum number of simultaneous outstanding interactions
   that endpoint maintains to a given server (including proxies)"""

#   +-------------------+---------------+
#   | name              | default value |
#   +-------------------+---------------+
#   | MAX_TRANSMIT_SPAN |          45 s |
#   | MAX_TRANSMIT_WAIT |          93 s |
#   | MAX_LATENCY       |         100 s |
#   | PROCESSING_DELAY  |           2 s |
#   | MAX_RTT           |         202 s |
#   | EXCHANGE_LIFETIME |         247 s |
#   | NON_LIFETIME      |         145 s |
#   +-------------------+---------------+

MAX_TRANSMIT_SPAN = ACK_TIMEOUT * (2 ** MAX_RETRANSMIT - 1) * ACK_RANDOM_FACTOR
"""Maximum time from the first transmission
of a confirmable message to its last retransmission."""

MAX_TRANSMIT_WAIT = ACK_TIMEOUT * (2 ** (MAX_RETRANSMIT + 1) - 1) * ACK_RANDOM_FACTOR
"""Maximum time from the first transmission
of a confirmable message to the time when the sender gives up on
receiving an acknowledgement or reset."""

MAX_LATENCY = 100.0
"""Maximum time a datagram is expected to take from the start
of its transmission to the completion of its reception."""

PROCESSING_DELAY = ACK_TIMEOUT
""""Time a node takes to turn around a
confirmable message into an acknowledgement."""

MAX_RTT = 2 * MAX_LATENCY + PROCESSING_DELAY
"""Maximum round-trip time."""

EXCHANGE_LIFETIME = MAX_TRANSMIT_SPAN + MAX_RTT
"""time from starting to send a confirmable
 message to the time when an acknowledgement is no longer expected,
i.e. message layer information about the message exchange can be purged"""

DEFAULT_BLOCK_SIZE_EXP = 2  # Block size 64
"""Default size exponent for blockwise transfers."""

EMPTY_ACK_DELAY = 0.1
"""After this time protocol sends empty ACK, and separate response"""

REQUEST_TIMEOUT = MAX_TRANSMIT_WAIT
"""Time after which server assumes it won't receive any answer.
   It is not defined by IETF documents.
   For human-operated devices it might be preferable to set some small value
   (for example 10 seconds)
   For M2M it's application dependent."""

CON = 0
"""Confirmable message type."""

NON = 1
"""Non-confirmable message type."""

ACK = 2
"""Acknowledgement message type."""

RST = 3
"""Reset message type"""

types = {0: 'CON',
         1: 'NON',
         2: 'ACK',
         3: 'RST'}


EMPTY = 0
GET = 1
POST = 2
PUT = 3
DELETE = 4
CREATED = 65
DELETED = 66
VALID = 67
CHANGED = 68
CONTENT = 69
CONTINUE = 95
BAD_REQUEST = 128
UNAUTHORIZED = 129
BAD_OPTION = 130
FORBIDDEN = 131
NOT_FOUND = 132
METHOD_NOT_ALLOWED = 133
NOT_ACCEPTABLE = 134
REQUEST_ENTITY_INCOMPLETE = 136
PRECONDITION_FAILED = 140
REQUEST_ENTITY_TOO_LARGE = 141
UNSUPPORTED_MEDIA_TYPE = 143
INTERNAL_SERVER_ERROR = 160
NOT_IMPLEMENTED = 161
BAD_GATEWAY = 162
SERVICE_UNAVAILABLE = 163
GATEWAY_TIMEOUT = 164
PROXYING_NOT_SUPPORTED = 165

requests = {1: 'GET',
            2: 'POST',
            3: 'PUT',
            4: 'DELETE'}

requests_rev = {v:k for k, v in requests.items()}

responses = {65: '2.01 Created',
             66: '2.02 Deleted',
             67: '2.03 Valid',
             68: '2.04 Changed',
             69: '2.05 Content',
             95: '2.31 Continue',
             128: '4.00 Bad Request',
             129: '4.01 Unauthorized',
             130: '4.02 Bad Option',
             131: '4.03 Forbidden',
             132: '4.04 Not Found',
             133: '4.05 Method Not Allowed',
             134: '4.06 Not Acceptable',
             136: '4.08 Request Entity Incomplete',
             140: '4.12 Precondition Failed',
             141: '4.13 Request Entity Too Large',
             143: '4.15 Unsupported Media Type',
             160: '5.00 Internal Server Error',
             161: '5.01 Not Implemented',
             162: '5.02 Bad Gateway',
             163: '5.03 Service Unavailable',
             164: '5.04 Gateway Timeout',
             165: '5.05 Proxying Not Supported'}

responses_rev = {v:k for k, v in responses.items()}

#=============================================================================
# coap-18, block-14, observe-11
#=============================================================================
# +-----+---+---+---+---+----------------+------------+--------+-------------+
# | No. | C | U | N | R | Name           | Format     | Length | Default     |
# +-----+---+---+---+---+----------------+------------+--------+-------------+
# |   1 | x |   |   | x | If-Match       | opaque     | 0-8    | (none)      |
# |   3 | x | x | - |   | Uri-Host       | string     | 1-255  | (see below) |
# |   4 |   |   |   | x | ETag           | opaque     | 1-8    | (none)      |
# |   5 | x |   |   |   | If-None-Match  | empty      | 0      | (none)      |
# |   6 |   | x |   |   | Observe        | empty/uint | ?      | (none)      |
# |   7 | x | x | - |   | Uri-Port       | uint       | 0-2    | (see below) |
# |   8 |   |   |   | x | Location-Path  | string     | 0-255  | (none)      |
# |  11 | x | x | - | x | Uri-Path       | string     | 0-255  | (none)      |
# |  12 |   |   |   |   | Content-Format | uint       | 0-2    | (none)      |
# |  14 |   | x |   |   | Max-Age        | uint       | 0-4    | 60          |
# |  15 | x | x | - | x | Uri-Query      | string     | 0-255  | (none)      |
# |  17 | x |   |   |   | Accept         | uint       | 0-2    | (none)      |
# |  20 |   |   |   | x | Location-Query | string     | 0-255  | (none)      |
# |  23 | x | x | - | - | Block2         | uint       | 0-3    | (see below) |
# |  27 | x | x | - | - | Block1         | uint       | 0-3    | (see below) |
# |  28 |   |   | x |   | Size2          | uint       | 0-4    | (none)      |
# |  35 | x | x | - |   | Proxy-Uri      | string     | 1-1034 | (none)      |
# |  39 | x | x | - |   | Proxy-Scheme   | string     | 1-255  | (none)      |
# |  60 |   |   | x |   | Size1          | uint       | 0-4    | (none)      |
# +-----+---+---+---+---+----------------+------------+--------+-------------+
#=============================================================================
#
# This table should serve as a reference only. It does not confirm that
# txThings conforms to the documents above
#

IF_MATCH = 1
URI_HOST = 3
ETAG = 4
IF_NONE_MATCH = 5
OBSERVE = 6
URI_PORT = 7
LOCATION_PATH = 8
URI_PATH = 11
CONTENT_FORMAT = 12
MAX_AGE = 14
URI_QUERY = 15
ACCEPT = 17
LOCATION_QUERY = 20
BLOCK2 = 23
BLOCK1 = 27
SIZE2 = 28
PROXY_URI = 35
PROXY_SCHEME = 39
SIZE1 = 60

options = {1: 'If-Match',
           3: 'Uri-Host',
           4: 'ETag',
           5: 'If-None-Match',
           6: 'Observe',
           7: 'Uri-Port',
           8: 'Location-Path',
           11: 'Uri-Path',
           12: 'Content-Format',
           14: 'Max-Age',
           15: 'Uri-Query',
           17: 'Accept',
           20: 'Location-Query',
           23: 'Block2',
           27: 'Block1',
           28: 'Size2',
           35: 'Proxy-Uri',
           39: 'Proxy-Scheme',
           60: 'Size1'}

options_rev = {v:k for k, v in options.items()}

media_types = {0: 'text/plain',
               40: 'application/link-format',
               41: 'application/xml',
               42: 'application/octet-stream',
               47: 'application/exi',
               50: 'application/json'}
"""A map from CoAP-assigned integral codes to Internet media type descriptions."""

media_types_rev = {v:k for k, v in media_types.items()}


class Message(object):
    """A CoAP Message."""

    def __init__(self, mtype=None, mid=None, code=EMPTY, payload='', token=''):
        self.version = 1
        self.mtype = mtype
        self.mid = mid
        self.code = code
        self.token = token
        self.payload = payload
        self.opt = Options()

        self.response_type = None
        self.remote = None
        self.prepath = None
        self.postpath = None

        if self.payload is None:
            raise TypeError("Payload must not be None. Use empty string instead.")

    @classmethod
    def decode(cls, rawdata, remote=None, protocol=None):
        """Create Message object from binary representation of message."""
        (vttkl, code, mid) = struct.unpack('!BBH', rawdata[:4])
        version = (vttkl & 0xC0) >> 6
        if version is not 1:
            raise ValueError("Fatal Error: Protocol Version must be 1")
        mtype = (vttkl & 0x30) >> 4
        token_length = (vttkl & 0x0F)
        msg = Message(mtype=mtype, mid=mid, code=code)
        msg.token = rawdata[4:4 + token_length]
        msg.payload = msg.opt.decode(rawdata[4 + token_length:])
        msg.remote = remote
        msg.protocol = protocol
        return msg

    def encode(self):
        """Create binary representation of message from Message object."""
        if self.mtype is None or self.mid is None:
            raise TypeError("Fatal Error: Message Type and Message ID must not be None.")
        rawdata = chr((self.version << 6) + ((self.mtype & 0x03) << 4) + (len(self.token) & 0x0F))
        rawdata += struct.pack('!BH', self.code, self.mid)
        rawdata += self.token
        rawdata += self.opt.encode()
        if len(self.payload) > 0:
            rawdata += chr(0xFF)
            rawdata += self.payload
        return rawdata

    def extractBlock(self, number, size_exp):
        """Extract block from current message."""
        size = 2 ** (size_exp + 4)
        start = number * size
        if start < len(self.payload):
            end = start + size if start + size < len(self.payload) else len(self.payload)
            block = copy.deepcopy(self)
            block.payload = block.payload[start:end]
            block.mid = None
            more = True if end < len(self.payload) else False
            if isRequest(block.code):
                block.opt.block1 = (number, more, size_exp)
            else:
                block.opt.block2 = (number, more, size_exp)
            return block

    def appendRequestBlock(self, next_block):
        """Append next block to current request message.
           Used when assembling incoming blockwise requests."""
        if isRequest(self.code):
            block1 = next_block.opt.block1
            if block1.block_number * (2 ** (block1.size_exponent + 4)) == len(self.payload):
                self.payload += next_block.payload
                self.opt.block1 = block1
                self.token = next_block.token
                self.mid = next_block.mid
                self.response_type = None
            else:
                raise iot.error.NotImplemented()
        else:
            raise ValueError("Fatal Error: called appendRequestBlock on non-request message!!!")

    def appendResponseBlock(self, next_block):
        """Append next block to current response message.
           Used when assembling incoming blockwise responses."""
        if isResponse(self.code):
            ## @TODO: check etags for consistency
            block2 = next_block.opt.block2
            if block2.block_number * (2 ** (block2.size_exponent + 4)) != len(self.payload):
                raise iot.error.NotImplemented()

            if next_block.opt.etag != self.opt.etag:
                raise iot.error.ResourceChanged()

            self.payload += next_block.payload
            self.opt.block2 = block2
            self.token = next_block.token
            self.mid = next_block.mid
        else:
            raise ValueError("Fatal Error: called appendResponseBlock on non-response message!!!")

    def generateNextBlock2Request(self, response):
        """Generate a request for next response block.
           This method is used by client after receiving
           blockwise response from server with "more" flag set."""
        request = copy.deepcopy(self)
        request.payload = ""
        request.mid = None
        if response.opt.block2.block_number == 0 and response.opt.block2.size_exponent > DEFAULT_BLOCK_SIZE_EXP:
            new_size_exponent = DEFAULT_BLOCK_SIZE_EXP
            new_block_number = 2 ** (response.opt.block2.size_exponent - new_size_exponent)
            request.opt.block2 = (new_block_number, False, new_size_exponent)
        else:
            request.opt.block2 = (response.opt.block2.block_number + 1, False, response.opt.block2.size_exponent)
        request.opt.deleteOption(BLOCK1)
        request.opt.deleteOption(OBSERVE)
        return request

    def generateNextBlock1Response(self):
        """Generate a response to acknowledge incoming request block.
           This method is used by server after receiving
           blockwise request from client with "more" flag set."""
        response = Message(code=CHANGED, token=self.token )
        response.remote = self.remote
        if self.opt.block1.block_number == 0 and self.opt.block1.size_exponent > DEFAULT_BLOCK_SIZE_EXP:
            new_size_exponent = DEFAULT_BLOCK_SIZE_EXP
            response.opt.block1 = (0, True, new_size_exponent)
        else:
            response.opt.block1 = (self.opt.block1.block_number, True, self.opt.block1.size_exponent)
        return response


class Options(object):
    """Represent CoAP Header Options."""
    def __init__(self):
        self._options = {}

    def decode(self, rawdata):
        """Decode all options in message from raw binary data."""
        option_number = 0

        while len(rawdata) > 0:
            if ord(rawdata[0]) == 0xFF:
                return rawdata[1:]
            dllen = ord(rawdata[0])
            delta = (dllen & 0xF0) >> 4
            length = (dllen & 0x0F)
            rawdata = rawdata[1:]
            (delta, rawdata) = readExtendedFieldValue(delta, rawdata)
            (length, rawdata) = readExtendedFieldValue(length, rawdata)
            option_number += delta
            option = option_formats.get(option_number, StringOption)(option_number)
            option.decode(rawdata[:length])
            self.addOption(option)
            rawdata = rawdata[length:]
        return ''

    def encode(self):
        """Encode all options in option header into string of bytes."""
        data = []
        current_opt_num = 0
        option_list = self.optionList()
        for option in option_list:
            delta, extended_delta = writeExtendedFieldValue(option.number - current_opt_num)
            length, extended_length = writeExtendedFieldValue(option.length)
            data.append(chr(((delta & 0x0F) << 4) + (length & 0x0F)))
            data.append(extended_delta)
            data.append(extended_length)
            data.append(option.encode())
            current_opt_num = option.number
        return (''.join(data))

    def addOption(self, option):
        """Add option into option header."""
        self._options.setdefault(option.number, []).append(option)

    def deleteOption(self, number):
        """Delete option from option header."""
        if number in self._options:
            self._options.pop(number)

    def getOption (self, number):
        """Get option with specified number."""
        return self._options.get(number)

    def optionList(self):
        return chain.from_iterable(sorted(self._options.values(), key=lambda x: x[0].number))

    def _setUriPath(self, segments):
        """Convenience setter: Uri-Path option"""
        if isinstance(segments, basestring): #For Python >3.1 replace with isinstance(segments,str)
            raise ValueError("URI Path should be passed as a list or tuple of segments")
        self.deleteOption(number=URI_PATH)
        for segment in segments:
            self.addOption(StringOption(number=URI_PATH, value=str(segment)))

    def _getUriPath(self):
        """Convenience getter: Uri-Path option"""
        segment_list = []
        uri_path = self.getOption(number=URI_PATH)
        if uri_path is not None:
            for segment in uri_path:
                segment_list.append(segment.value)
        return segment_list

    uri_path = property(_getUriPath, _setUriPath)

    def _setUriQuery(self, segments):
        """Convenience setter: Uri-Query option"""
        if isinstance(segments, basestring): #For Python >3.1 replace with isinstance(segments,str)
            raise ValueError("URI Query should be passed as a list or tuple of segments")
        self.deleteOption(number=URI_QUERY)
        for segment in segments:
            self.addOption(StringOption(number=URI_QUERY, value=str(segment)))

    def _getUriQuery(self):
        """Convenience getter: Uri-Query option"""
        segment_list = []
        uri_query = self.getOption(number=URI_QUERY)
        if uri_query is not None:
            for segment in uri_query:
                segment_list.append(segment.value)
        return segment_list

    uri_query = property(_getUriQuery, _setUriQuery)

    def _setBlock2(self, block_tuple):
        """Convenience setter: Block2 option"""
        self.deleteOption(number=BLOCK2)
        self.addOption(BlockOption(number=BLOCK2, value=block_tuple))

    def _getBlock2(self):
        """Convenience getter: Block2 option"""
        block2 = self.getOption(number=BLOCK2)
        if block2 is not None:
            return block2[0].value
        else:
            return None

    block2 = property(_getBlock2, _setBlock2)

    def _setBlock1(self, block_tuple):
        """Convenience setter: Block1 option"""
        self.deleteOption(number=BLOCK1)
        self.addOption(BlockOption(number=BLOCK1, value=block_tuple))

    def _getBlock1(self):
        """Convenience getter: Block1 option"""
        block1 = self.getOption(number=BLOCK1)
        if block1 is not None:
            return block1[0].value
        else:
            return None

    block1 = property(_getBlock1, _setBlock1)

    def _setContentFormat(self, content_format):
        """Convenience setter: Content-Format option"""
        self.deleteOption(number=CONTENT_FORMAT)
        self.addOption(UintOption(number=CONTENT_FORMAT, value=content_format))

    def _getContentFormat(self):
        """Convenience getter: Content-Format option"""
        content_format = self.getOption(number=CONTENT_FORMAT)
        if content_format is not None:
            return content_format[0].value
        else:
            return None

    content_format = property(_getContentFormat, _setContentFormat)

    def _setETag(self, etag):
        """Convenience setter: ETag option"""
        self.deleteOption(number=ETAG)
        if etag is not None:
            self.addOption(StringOption(number=ETAG, value=etag))

    def _getETag(self):
        """Convenience getter: ETag option"""
        etag = self.getOption(number=ETAG)
        if etag is not None:
            return etag[0].value
        else:
            return None

    etag = property(_getETag, _setETag, None, "Access to a single ETag on the message (as used in responses)")

    def _setETags(self, etags):
        self.deleteOption(number=ETAG)
        for tag in etags:
            self.addOption(StringOption(number=ETAG, value=tag))

    def _getETags(self):
        etag = self.getOption(number=ETAG)
        return [] if etag is None else [tag.value for tag in etag]

    etags = property(_getETags, _setETags, None, "Access to a list of ETags on the message (as used in requests)")

    def _setObserve(self, observe):
        self.deleteOption(number=OBSERVE)
        if observe is not None:
            self.addOption(UintOption(number=OBSERVE, value=observe))

    def _getObserve(self):
        observe = self.getOption(number=OBSERVE)
        if observe is not None:
            return observe[0].value
        else:
            return None

    observe = property(_getObserve, _setObserve)

    def _setAccept(self, accept):
        self.deleteOption(number=ACCEPT)
        if accept is not None:
            self.addOption(UintOption(number=ACCEPT, value=accept))

    def _getAccept(self):
        accept = self.getOption(number=ACCEPT)
        if accept is not None:
            return accept[0].value
        else:
            return None

    accept = property(_getAccept, _setAccept)


def readExtendedFieldValue(value, rawdata):
    """Used to decode large values of option delta and option length
       from raw binary form."""
    if value >= 0 and value < 13:
        return (value, rawdata)
    elif value == 13:
        return (ord(rawdata[0]) + 13, rawdata[1:])
    elif value == 14:
        return (struct.unpack('!H', rawdata[:2])[0] + 269, rawdata[2:])
    else:
        raise ValueError("Value out of range.")


def writeExtendedFieldValue(value):
    """Used to encode large values of option delta and option length
       into raw binary form.
       In CoAP option delta and length can be represented by a variable
       number of bytes depending on the value."""
    if value >= 0 and value < 13:
        return (value, '')
    elif value >= 13 and value < 269:
        return (13, struct.pack('!B', value - 13))
    elif value >= 269 and value < 65804:
        return (14, struct.pack('!H', value - 269))
    else:
        raise ValueError("Value out of range.")


class StringOption(object):
    """String CoAP option - used to represent string and opaque options."""

    def __init__(self, number, value=""):
        self.value = value
        self.number = number

    def encode(self):
        rawdata = self.value
        return rawdata

    def decode(self, rawdata):
        self.value = rawdata  # if rawdata is not None else ""

    def _length(self):
        return len(self.value)
    length = property(_length)


class UintOption(object):
    """Uint CoAP option - used to represent uint options."""

    def __init__(self, number, value=0):
        self.value = value
        self.number = number

    def encode(self):
        rawdata = struct.pack("!L", self.value)  # For Python >3.1 replace with int.to_bytes()
        return rawdata.lstrip(chr(0))

    def decode(self, rawdata):  # For Python >3.1 replace with int.from_bytes()
        value = 0
        for byte in rawdata:
            value = (value * 256) + ord(byte)
        self.value = value
        return self

    def _length(self):
        if self.value > 0:
            return (self.value.bit_length() - 1) // 8 + 1
        else:
            return 0
    length = property(_length)


class BlockOption(object):
    """Block CoAP option - special option used only for Block1 and Block2 options.
       Currently it is the only type of CoAP options that has
       internal structure."""
    BlockwiseTuple = collections.namedtuple('BlockwiseTuple', ['block_number', 'more', 'size_exponent'])

    def __init__(self, number, value=(0, None, 0)):
        self.value = self.BlockwiseTuple._make(value)
        self.number = number

    def encode(self):
        as_integer = (self.value[0] << 4) + (self.value[1] * 0x08) + self.value[2]
        rawdata = struct.pack("!L", as_integer)  # For Python >3.1 replace with int.to_bytes()
        return rawdata.lstrip(chr(0))

    def decode(self, rawdata):
        as_integer = 0
        for byte in rawdata:
            as_integer = (as_integer * 256) + ord(byte)
        self.value = self.BlockwiseTuple(block_number=(as_integer >> 4), more=bool(as_integer & 0x08), size_exponent=(as_integer & 0x07))

    def _length(self):
        return ((self.value[0].bit_length() + 3) / 8 + 1)
    length = property(_length)

option_formats = {6: UintOption,
                  7: UintOption,
                  12: UintOption,
                  14: UintOption,
                  16: UintOption,
                  23: BlockOption,
                  27: BlockOption,
                  28: UintOption}
"""Dictionary used to assign option type to option numbers."""


def isRequest(code):
    return True if (code >= 1 and code < 32) else False


def isResponse(code):
    return True if (code >= 64 and code < 192) else False


def isSuccessful(code):
    return True if (code >= 64 and code < 96) else False


def uriPathAsString(segment_list):
    return '/' + '/'.join(segment_list)

def humanFormatMessage(msg):
    try:
        print("Message Type:    {}".format(types[msg.mtype]))
        print("Message Id:      0x{}".format(msg.mid))
        print("Message Code:    {}".format(responses[msg.code]))
        print("Message Token:   0x{}".format(msg.token))
        print("Message Options: {}".format(msg.opt))
        print("Message Payload: {}".format(msg.payload))
    except KeyError:
        print("Improperly Formatted Message!")