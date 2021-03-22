########################################
# Autogenerated by cmfc. Do not modify.
########################################

# Concord
#
# Copyright (c) 2020 VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache 2.0 license (the 'License').
# You may not use this product except in compliance with the Apache 2.0 License.
#
# This product may include a number of subcomponents with separate copyright
# notices and license terms. Your use of these subcomponents is subject to the
# terms and conditions of the subcomponent's license, as noted in the LICENSE
# file.

import struct


def is_primitive(s):
    return s in [
        'bool', 'string', 'bytes', 'uint8', 'uint16', 'uint32', 'uint64',
        'int8', 'int16', 'int32', 'int64'
    ]


class CmfSerializeError(Exception):
    def __init__(self, msg):
        self.message = f'CmfSerializeError: {msg}'

    def __str__(self):
        return self.message


class CmfDeserializeError(Exception):
    def __init__(self, msg):
        self.message = f'CmfDeserializeError: {msg}'

    def __str__(self):
        return self.message


class NoDataLeftError(CmfDeserializeError):
    def __init__(self):
        super().__init__(
            'Data left in buffer is less than what is needed for deserialization'
        )


class BadDataError(CmfDeserializeError):
    def __init__(self, expected, actual):
        super().__init__(f'Expected {expected}, got {actual}')


class CMFSerializer():
    def __init__(self):
        self.buf = bytearray()

    def validate_int(self, val, min, max):
        if not type(val) is int:
            raise CmfSerializeError(f'Expected integer value, got {type(val)}')
        if val < min:
            raise CmfSerializeError(
                f'Expected integer value less than {min}, got {val}')
        if val > max:
            raise CmfSerializeError(
                f'Expected integer value less than {max}, got {val}')

    def serialize(self, val, serializers, fixed_size=None):
        '''
        Serialize any nested types in by applying the methods in `serializers` at each level.
        This method interacts with those below in a mutually recursive manner for nested types.
        '''
        s = serializers[0]
        if s in ['fixedlist'] and len(serializers) > 1:
            getattr(self, s)(val, serializers[1:], fixed_size)
        elif s in ['list', 'optional'] and len(serializers) > 1:
            getattr(self, s)(val, serializers[1:])
        elif s in ['kvpair', 'map'] and len(serializers) > 2:
            getattr(self, s)(val, serializers[1:])
        elif type(s) is tuple and len(s) == 2 and s[0] == 'oneof' and type(
                s[1]) is dict:
            self.oneof(val, s[1])
        elif type(s) is tuple and len(s) == 2 and s[0] == 'msg' and type(
                s[1]) is str:
            self.msg(val, s[1])
        elif is_primitive(s):
            getattr(self, s)(val)
        else:
            raise CmfSerializeError(f'Invalid serializer: {s}, val = {val}')

    ###
    # Serialization functions for types that compose fields
    ###
    def bool(self, val):
        if not type(val) is bool:
            raise CmfSerializeError(f'Expected bool, got {type(val)}')
        if val:
            self.buf.append(1)
        else:
            self.buf.append(0)

    def uint8(self, val):
        self.validate_int(val, 0, 255)
        self.buf.extend(struct.pack('B', val))

    def uint16(self, val):
        self.validate_int(val, 0, 65536)
        self.buf.extend(struct.pack('>H', val))

    def uint32(self, val):
        self.validate_int(val, 0, 4294967296)
        self.buf.extend(struct.pack('>I', val))

    def uint64(self, val):
        self.validate_int(val, 0, 18446744073709551616)
        self.buf.extend(struct.pack('>Q', val))

    def int8(self, val):
        self.validate_int(val, -128, 127)
        self.buf.extend(struct.pack('b', val))

    def int16(self, val):
        self.validate_int(val, -32768, 32767)
        self.buf.extend(struct.pack('>h', val))

    def int32(self, val):
        self.validate_int(val, -2147483648, 2147483647)
        self.buf.extend(struct.pack('>i', val))

    def int64(self, val):
        self.validate_int(val, -9223372036854775808, 9223372036854775807)
        self.buf.extend(struct.pack('>q', val))

    def string(self, val):
        if not type(val) is str:
            raise CmfSerializeError(f'Expected string, got {type(val)}')
        self.uint32(len(val))
        self.buf.extend(bytes(val, 'utf-8'))

    def bytes(self, val):
        if not type(val) in [bytes, bytearray]:
            raise CmfSerializeError(f'Expected bytes, got {type(val)}')
        self.uint32(len(val))
        self.buf.extend(val)

    def msg(self, msg, msg_name):
        if msg.__class__.__name__ != msg_name:
            raise CmfSerializeError(
                f'Expected {msg_name}, got {msg.__class__.__name__}')
        self.buf.extend(msg.serialize())

    def kvpair(self, pair, serializers):
        if not type(pair) is tuple:
            raise CmfSerializeError(f'Expected tuple, got {type(pair)}')
        self.serialize(pair[0], serializers)
        self.serialize(pair[1], serializers[1:])

    def list(self, items, serializers):
        if not type(items) is list:
            raise CmfSerializeError(f'Expected list, got {type(items)}')
        self.uint32(len(items))
        for val in items:
            self.serialize(val, serializers)

    def fixedlist(self, items, serializers, fixed_size):
        if not type(items) is list:
            raise CmfSerializeError(f'Expected list, got {type(items)}')
        if len(items) != fixed_size:
            raise CmfSerializeError(f'Expected list size of {fixed_size}, got {len(items)}')
        for val in items:
            self.serialize(val, serializers)

    def map(self, dictionary, serializers):
        if not type(dictionary) is dict:
            raise CmfSerializeError(f'Expected dict, got {type(dictionary)}')
        self.uint32(len(dictionary))
        for k, v in sorted(dictionary.items()):
            self.serialize(k, serializers)
            self.serialize(v, serializers[1:])

    def optional(self, val, serializers):
        if val is None:
            self.bool(False)
        else:
            self.bool(True)
            self.serialize(val, serializers)

    def oneof(self, val, msgs):
        if val.__class__.__name__ in msgs.keys():
            self.uint32(val.id)
            self.buf.extend(val.serialize())
        else:
            raise CmfSerializeError(
                f'Invalid msg in oneof: {val.__class__.__name__}')


class CMFDeserializer():
    def __init__(self, buf):
        self.buf = buf
        self.pos = 0

    def deserialize(self, serializers, fixed_size=None):
        '''
        Recursively deserialize `self.buf` using `serializers`
        '''
        s = serializers[0]
        if s in ['fixedlist'] and len(serializers) > 1:
            return getattr(self, s)(serializers[1:], fixed_size)
        elif s in ['list', 'optional'] and len(serializers) > 1:
            return getattr(self, s)(serializers[1:])
        elif s in ['kvpair', 'map'] and len(serializers) > 2:
            return getattr(self, s)(serializers[1:])
        elif type(s) is tuple and len(s) == 2 and s[0] == 'oneof' and type(
                s[1]) is dict:
            return self.oneof(s[1])
        elif type(s) is tuple and len(s) == 2 and s[0] == 'msg' and type(
                s[1]) is str:
            return self.msg(s[1])
        elif is_primitive(s):
            return getattr(self, s)()
        else:
            raise CmfDeserializeError(f'Invalid serializer: {s}')

    def bool(self):
        if self.pos + 1 > len(self.buf):
            raise NoDataLeftError()
        val = self.buf[self.pos]
        if val == 1:
            self.pos += 1
            return True
        elif val == 0:
            self.pos += 1
            return False
        raise BadDataError('0 or 1', val)

    def uint8(self):
        if self.pos + 1 > len(self.buf):
            raise NoDataLeftError()
        val = struct.unpack_from('B', self.buf, self.pos)
        self.pos += 1
        return val[0]

    def uint16(self):
        if self.pos + 2 > len(self.buf):
            raise NoDataLeftError()
        val = struct.unpack_from('>H', self.buf, self.pos)
        self.pos += 2
        return val[0]

    def uint32(self):
        if self.pos + 4 > len(self.buf):
            raise NoDataLeftError()
        val = struct.unpack_from('>I', self.buf, self.pos)
        self.pos += 4
        return val[0]

    def uint64(self):
        if self.pos + 8 > len(self.buf):
            raise NoDataLeftError()
        val = struct.unpack_from('>Q', self.buf, self.pos)
        self.pos += 8
        return val[0]

    def int8(self):
        if self.pos + 1 > len(self.buf):
            raise NoDataLeftError()
        val = struct.unpack_from('b', self.buf, self.pos)
        self.pos += 1
        return val[0]

    def int16(self):
        if self.pos + 2 > len(self.buf):
            raise NoDataLeftError()
        val = struct.unpack_from('>h', self.buf, self.pos)
        self.pos += 2
        return val[0]

    def int32(self):
        if self.pos + 4 > len(self.buf):
            raise NoDataLeftError()
        val = struct.unpack_from('>i', self.buf, self.pos)
        self.pos += 4
        return val[0]

    def int64(self):
        if self.pos + 8 > len(self.buf):
            raise NoDataLeftError()
        val = struct.unpack_from('>q', self.buf, self.pos)
        self.pos += 8
        return val[0]

    def string(self):
        size = self.uint32()
        if self.pos + size > len(self.buf):
            raise NoDataLeftError()
        val = str(self.buf[self.pos:self.pos + size], 'utf-8')
        self.pos += size
        return val

    def bytes(self):
        size = self.uint32()
        if self.pos + size > len(self.buf):
            raise NoDataLeftError()
        val = self.buf[self.pos:self.pos + size]
        self.pos += size
        return val

    def msg(self, msg_name):
        cls = globals()[msg_name]
        val, bytes_read = cls.deserialize(self.buf[self.pos:])
        self.pos += bytes_read
        return val

    def kvpair(self, serializers):
        key = self.deserialize(serializers)
        val = self.deserialize(serializers[1:])
        return (key, val)

    def list(self, serializers):
        size = self.uint32()
        return [self.deserialize(serializers) for _ in range(0, size)]

    def fixedlist(self, serializers, fixed_size):
        return [self.deserialize(serializers) for _ in range(0, fixed_size)]

    def map(self, serializers):
        size = self.uint32()
        # We can't use a dict comprehension here unless we rely on python 3.8, since order of
        # evaluation of dict comprehensions constructs values first.
        # See: https://stackoverflow.com/questions/42201932/order-of-operations-in-a-dictionary-comprehension
        rv = dict()
        for _ in range(0, size):
            key = self.deserialize(serializers)
            val = self.deserialize(serializers[1:])
            rv[key] = val
        return rv

    def optional(self, serializers):
        if not self.bool():
            return None
        return self.deserialize(serializers)

    def oneof(self, msgs):
        id = self.uint32()
        if id not in msgs.values():
            raise CmfDeserializeError(f'Invalid msg id for oneof: {id}')
        for name, msg_id in msgs.items():
            if msg_id == id:
                return self.msg(name)


class WedgeCommand():
    ''' A CMF message for WedgeCommand '''
    id = 3

    def __init__(self):
         self.stop_seq_num = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.stop_seq_num, ['uint64'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.stop_seq_num = deserializer.deserialize(['uint64'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.stop_seq_num != other.stop_seq_num:
            return False
        return True

class WedgeStatusRequest():
    ''' A CMF message for WedgeStatusRequest '''
    id = 5

    def __init__(self):
         self.sender = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.sender, ['uint64'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.sender = deserializer.deserialize(['uint64'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.sender != other.sender:
            return False
        return True

class WedgeStatusResponse():
    ''' A CMF message for WedgeStatusResponse '''
    id = 6

    def __init__(self):
         self.stopped = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.stopped, ['bool'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.stopped = deserializer.deserialize(['bool'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.stopped != other.stopped:
            return False
        return True

class DownloadCommand():
    ''' A CMF message for DownloadCommand '''
    id = 9

    def __init__(self):
         self.version = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.version, ['string'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.version = deserializer.deserialize(['string'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.version != other.version:
            return False
        return True

class DownloadStatusCommand():
    ''' A CMF message for DownloadStatusCommand '''
    id = 10

    def __init__(self):
         self.version = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.version, ['string'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.version = deserializer.deserialize(['string'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.version != other.version:
            return False
        return True

class DownloadStatus():
    ''' A CMF message for DownloadStatus '''
    id = 11

    def __init__(self):
         self.download_completed = None
         self.in_progress = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.download_completed, ['bool'], None)
        serializer.serialize(self.in_progress, ['bool'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.download_completed = deserializer.deserialize(['bool'], None)
        obj.in_progress = deserializer.deserialize(['bool'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.download_completed != other.download_completed:
            return False
        if self.in_progress != other.in_progress:
            return False
        return True

class TestCommand():
    ''' A CMF message for TestCommand '''
    id = 12

    def __init__(self):
         self.test = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.test, ['string'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.test = deserializer.deserialize(['string'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.test != other.test:
            return False
        return True

class LatestPrunableBlockRequest():
    ''' A CMF message for LatestPrunableBlockRequest '''
    id = 13

    def __init__(self):
         self.sender = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.sender, ['uint64'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.sender = deserializer.deserialize(['uint64'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.sender != other.sender:
            return False
        return True

class LatestPrunableBlock():
    ''' A CMF message for LatestPrunableBlock '''
    id = 14

    def __init__(self):
         self.replica = None
         self.block_id = None
         self.bft_sequence_number = None
         self.signature = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.replica, ['uint64'], None)
        serializer.serialize(self.block_id, ['uint64'], None)
        serializer.serialize(self.bft_sequence_number, ['uint64'], None)
        serializer.serialize(self.signature, ['bytes'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.replica = deserializer.deserialize(['uint64'], None)
        obj.block_id = deserializer.deserialize(['uint64'], None)
        obj.bft_sequence_number = deserializer.deserialize(['uint64'], None)
        obj.signature = deserializer.deserialize(['bytes'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.replica != other.replica:
            return False
        if self.block_id != other.block_id:
            return False
        if self.bft_sequence_number != other.bft_sequence_number:
            return False
        if self.signature != other.signature:
            return False
        return True

class PruneRequest():
    ''' A CMF message for PruneRequest '''
    id = 15

    def __init__(self):
         self.sender = None
         self.latest_prunable_block = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.sender, ['uint64'], None)
        serializer.serialize(self.latest_prunable_block, ['list', ('msg', 'LatestPrunableBlock')], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.sender = deserializer.deserialize(['uint64'], None)
        obj.latest_prunable_block = deserializer.deserialize(['list', ('msg', 'LatestPrunableBlock')], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.sender != other.sender:
            return False
        if self.latest_prunable_block != other.latest_prunable_block:
            return False
        return True

class PruneStatusRequest():
    ''' A CMF message for PruneStatusRequest '''
    id = 17

    def __init__(self):
         self.sender = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.sender, ['uint64'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.sender = deserializer.deserialize(['uint64'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.sender != other.sender:
            return False
        return True

class PruneStatus():
    ''' A CMF message for PruneStatus '''
    id = 18

    def __init__(self):
         self.sender = None
         self.in_progress = None
         self.last_pruned_block = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.sender, ['uint64'], None)
        serializer.serialize(self.in_progress, ['bool'], None)
        serializer.serialize(self.last_pruned_block, ['uint64'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.sender = deserializer.deserialize(['uint64'], None)
        obj.in_progress = deserializer.deserialize(['bool'], None)
        obj.last_pruned_block = deserializer.deserialize(['uint64'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.sender != other.sender:
            return False
        if self.in_progress != other.in_progress:
            return False
        if self.last_pruned_block != other.last_pruned_block:
            return False
        return True

class GetVersionCommand():
    ''' A CMF message for GetVersionCommand '''
    id = 19

    def __init__(self):
         self.place_holder = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.place_holder, ['bytes'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.place_holder = deserializer.deserialize(['bytes'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.place_holder != other.place_holder:
            return False
        return True

class InstallCommand():
    ''' A CMF message for InstallCommand '''
    id = 20

    def __init__(self):
         self.version = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.version, ['string'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.version = deserializer.deserialize(['string'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.version != other.version:
            return False
        return True

class InstallStatusCommand():
    ''' A CMF message for InstallStatusCommand '''
    id = 21

    def __init__(self):
         self.version = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.version, ['optional', 'string'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.version = deserializer.deserialize(['optional', 'string'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.version != other.version:
            return False
        return True

class InstallStatusResponse():
    ''' A CMF message for InstallStatusResponse '''
    id = 22

    def __init__(self):
         self.version = None
         self.in_progress = None
         self.install_completed = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.version, ['string'], None)
        serializer.serialize(self.in_progress, ['bool'], None)
        serializer.serialize(self.install_completed, ['bool'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.version = deserializer.deserialize(['string'], None)
        obj.in_progress = deserializer.deserialize(['bool'], None)
        obj.install_completed = deserializer.deserialize(['bool'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.version != other.version:
            return False
        if self.in_progress != other.in_progress:
            return False
        if self.install_completed != other.install_completed:
            return False
        return True

class GetVersionResponse():
    ''' A CMF message for GetVersionResponse '''
    id = 23

    def __init__(self):
         self.version = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.version, ['string'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.version = deserializer.deserialize(['string'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.version != other.version:
            return False
        return True

class ReconfigurationErrorMsg():
    ''' A CMF message for ReconfigurationErrorMsg '''
    id = 24

    def __init__(self):
         self.error_msg = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.error_msg, ['string'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.error_msg = deserializer.deserialize(['string'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.error_msg != other.error_msg:
            return False
        return True

class ReconfigurationRequest():
    ''' A CMF message for ReconfigurationRequest '''
    id = 1

    def __init__(self):
         self.signature = None
         self.command = None
         self.additional_data = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.signature, ['bytes'], None)
        serializer.serialize(self.command, [('oneof', {'WedgeCommand': 3, 'WedgeStatusRequest': 5, 'TestCommand': 12, 'GetVersionCommand': 19, 'DownloadCommand': 9, 'DownloadStatusCommand': 10, 'LatestPrunableBlockRequest': 13, 'PruneRequest': 15, 'PruneStatusRequest': 17, 'InstallCommand': 20, 'InstallStatusCommand': 21})], None)
        serializer.serialize(self.additional_data, ['bytes'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.signature = deserializer.deserialize(['bytes'], None)
        obj.command = deserializer.deserialize([('oneof', {'WedgeCommand': 3, 'WedgeStatusRequest': 5, 'TestCommand': 12, 'GetVersionCommand': 19, 'DownloadCommand': 9, 'DownloadStatusCommand': 10, 'LatestPrunableBlockRequest': 13, 'PruneRequest': 15, 'PruneStatusRequest': 17, 'InstallCommand': 20, 'InstallStatusCommand': 21})], None)
        obj.additional_data = deserializer.deserialize(['bytes'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.signature != other.signature:
            return False
        if self.command != other.command:
            return False
        if self.additional_data != other.additional_data:
            return False
        return True

class ReconfigurationResponse():
    ''' A CMF message for ReconfigurationResponse '''
    id = 2

    def __init__(self):
         self.success = None
         self.response = None
         self.additional_data = None


    def serialize(self) -> bytes:
        ''' Serialize this message in CMF format '''
        serializer = CMFSerializer()
        serializer.serialize(self.success, ['bool'], None)
        serializer.serialize(self.response, [('oneof', {'WedgeStatusResponse': 6, 'LatestPrunableBlock': 14, 'PruneStatus': 18, 'DownloadStatus': 11, 'InstallStatusResponse': 22, 'GetVersionResponse': 23, 'ReconfigurationErrorMsg': 24})], None)
        serializer.serialize(self.additional_data, ['bytes'], None)
        return serializer.buf

    @classmethod
    def deserialize(cls, buf):
        ''' Take bytes of a serialized CMF message, deserialize it, and return a new instance of this class. '''
        deserializer = CMFDeserializer(buf)
        obj = cls()
        obj.success = deserializer.deserialize(['bool'], None)
        obj.response = deserializer.deserialize([('oneof', {'WedgeStatusResponse': 6, 'LatestPrunableBlock': 14, 'PruneStatus': 18, 'DownloadStatus': 11, 'InstallStatusResponse': 22, 'GetVersionResponse': 23, 'ReconfigurationErrorMsg': 24})], None)
        obj.additional_data = deserializer.deserialize(['bytes'], None)
        return obj, deserializer.pos

    def __eq__(self, other):
        if self.success != other.success:
            return False
        if self.response != other.response:
            return False
        if self.additional_data != other.additional_data:
            return False
        return True