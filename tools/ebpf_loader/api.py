from ctypes import *


#
# Import common interface C module
#
ebpf_iface = CDLL("./libebpf_iface.so")
ebpf_iface.ebpf_load_prog.argtypes = [c_void_p, c_uint16, c_void_p, c_uint32]
ebpf_iface.ebpf_map_create.argtypes = [c_void_p, c_uint16, c_uint32, c_uint32, c_uint32, c_uint32]
ebpf_iface.ebpf_map_update_elem.argtypes = [c_void_p, c_int, c_void_p, c_void_p, c_uint64]
ebpf_iface.ebpf_map_lookup_elem.argtypes = [c_void_p, c_int, c_void_p, c_void_p, c_uint64]
ebpf_iface.ebpf_map_delete_elem.argtypes = [c_void_p, c_int, c_void_p]
ebpf_iface.ebpf_map_get_next_key.argtypes = [c_void_p, c_int, c_void_p, c_void_p]
ebpf_iface.ebpf_close_prog_desc.restype = None
ebpf_iface.ebpf_close_prog_desc.argtypes = [c_void_p, c_int]
ebpf_iface.ebpf_close_map_desc.restype = None
ebpf_iface.ebpf_close_map_desc.argtypes = [c_void_p, c_int]


# 
# Corresponding Python interface class. This is just an interface class.
# Should be subclassed.
#
class EBPFIface(object):
    def load_prog(self, prog_type, prog, prog_len):
        return ebpf_iface.ebpf_load_prog(self.inst, prog_type, prog, prog_len)

    def map_create(self, map_type, key_size, value_size, max_entries, flags):
        return ebpf_iface.ebpf_map_create(self.inst, map_type, key_size,
                value_size, max_entries, flags)


class EBPFMap(object):
    def __init__(self, iface, map_desc):
        self.iface = iface
        self.map_desc = map_desc

    def update_elem(self, key, value, flags):
        return ebpf_iface.ebpf_map_update_elem(self.iface.inst, self.map_desc, key, value, flags)

    def lookup_elem(self, key, value, flags):
        return ebpf_iface.ebpf_map_lookup_elem(self.iface.inst, self.map_desc, key, value, flags)

    def delete_elem(self, key):
        return ebpf_iface.ebpf_map_delete_elem(self.iface.inst, self.map_desc, key)


#
# Import ebpf-dev interface C module.
# Underlying C module implements all of ebpf-iface functions.
#
ebpf_dev_iface = CDLL("./libebpf_dev_iface.so")
ebpf_dev_iface.ebpf_dev_iface_create.restype = c_void_p
ebpf_dev_iface.ebpf_dev_iface_destroy.argtypes = [c_void_p]


#
# Subclass EBPFIface in here
#
class EBPFDevIface(EBPFIface):
    def __init__(self):
        super(EBPFDevIface, self).__init__()
        self.inst = ebpf_dev_iface.ebpf_dev_iface_create()

    def __del__(self, ebpf_dev_iface = ebpf_dev_iface):
        ebpf_dev_iface.ebpf_dev_iface_destroy(self.inst)


class EBPFMapDef(Structure):
    _fields_ = [
        ("type", c_uint32),
        ("key_size", c_uint32),
        ("value_size", c_uint32),
        ("max_entries", c_uint32),
        ("flags", c_uint32)
    ]


class EBPFMapEntry(Structure):
    _fields_ = [
        ("map_desc", c_int),
        ("name", c_char_p),
        ("def", POINTER(EBPFMapDef))
    ]


ebpf_loader = CDLL("./libebpf_loader.so")
ebpf_loader.ebpf_loader_create.restype = c_void_p
ebpf_loader.ebpf_loader_create.argtypes = [c_void_p]
ebpf_loader.ebpf_loader_execute.argtypes = [c_void_p, c_char_p, c_uint16]
ebpf_loader.ebpf_loader_destroy.restype = None
ebpf_loader.ebpf_loader_destroy.argtypes = [c_void_p]
ebpf_loader.ebpf_loader_get_map_num.restype = c_uint16
ebpf_loader.ebpf_loader_get_map_num.argtypes = [c_void_p]
ebpf_loader.ebpf_loader_get_map_entry.restype = POINTER(EBPFMapDef)
ebpf_loader.ebpf_loader_get_map_entry.argtypes = [c_void_p, c_uint16]


class EBPFLoader(object):
    def __init__(self, iface):
        self.iface = iface
        self.inst = ebpf_loader.ebpf_loader_create(iface.inst)
        self.map_entries = []

    def load(self, fname, prog_type):
        # error = ebpf_loader.ebpf_loader_execute(self.inst, fname, prog_type)
        # if error:
        #     raise Exception()

        ebpf_loader.ebpf_loader_execute(self.inst, fname, prog_type)

        # map_num = ebpf_loader.ebpf_loader_get_map_num(self.inst)

        # for i in range(0, map_num):
        #     ent = ebpf_loader.ebpf_loader_get_map_entry(self.inst, i)
        #     self.map_entries.append(ent)

    def __del__(self, ebpf_loader = ebpf_loader):
        ebpf_loader.ebpf_loader_destroy(self.inst)


# ebpf program type enumeration
EBPF_PROG_TYPE_TEST = 0


# ebpf map type enumeration
EBPF_MAP_TYPE_ARRAY = 0
EBPF_MAP_TYPE_TOMMYHASHTBL = 1


if __name__ == "__main__":
    iface = EBPFDevIface()
    loader = EBPFLoader(iface)
    loader.load("./test.o", EBPF_PROG_TYPE_TEST)
