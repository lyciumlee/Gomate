from typing import Type
import idc, idaapi, ida_bytes, ida_auto, ida_nalt
from idc_bc695 import AddAutoStkPnt2, ParseType
idaapi.require("moduledata")
idaapi.require("common")
from moduledata import ModuleData
import common
from common import ADDR_SZ

import sys
sys.setrecursionlimit(1000000)


log_file_this = open("C:\\Users\\lll\\Desktop\\log.txt", "w")


cache_parse_types = []

class TypesParser():
    '''
    Parse and construct all the types
    '''

    RAW_TYPES = ['Bool','Int','Int8','Int16','Int32','Int64','Uint','Uint8','Uint16','Uint32','Uint64','Uintptr','Float32','Float64','Complex64','Complex128', 'UnsafePointer', 'String']
    
    def __init__(self, firstmoduledata: ModuleData):
        self.moddata = firstmoduledata
        self.parsed_types = dict()
        self.itabs = list()
        self.depth = 0

    def is_raw_type(self, kind):
        return kind in self.RAW_TYPES

    def build_all_types(self, depth=1):
        common._info("Building all types...")
        # self.moddata.typelink_len
        log_file_this.write("type link len is %d \n" % self.moddata.typelink_len)
        log_file_this.flush()
        for idx in range(self.moddata.typelink_len):
            try:
                self.depth = 0
                type_off = idc.get_wide_dword(self.moddata.typelink_addr + idx * 4)
                idc.create_dword(self.moddata.typelink_addr + idx * 4)
                if type_off == 0:
                    continue
                type_addr = self.moddata.types_addr + type_off
                idc.set_cmt(self.moddata.typelink_addr + idx * 4, f"type @ {hex(type_addr)}", True)
                ida_auto.auto_wait()
                common._debug("%dth type, offset: 0x%x, addr: 0x%x" % (idx+1, type_off, type_addr))

                if type_addr in self.parsed_types.keys():
                    common._debug("  " * depth + 'already parsed')
                    continue
                log_file_this.write("start parse type_addr is 0x%x \n" % type_addr)
                log_file_this.flush()
                self.parse_type(type_addr=type_addr)
            except:
                # common._debug(sys.exc_info()[0])
                pass
        common._info("types building finished. Total types number: %d" % len(self.parsed_types.keys()))
        self.depth = 0
        # print(self.types_str_info)


    def parse_type(self, type_addr=idc.BADADDR, depth=1):
        common._debug("parse 0x%x types!" % type_addr)
        if type_addr in self.parsed_types.keys():
            common._debug("  "*depth + 'already parsed')
            return self.parsed_types[type_addr].rtype

        common._debug("Parsing type @ 0x%x" % type_addr)
        rtype = RType(type_addr, self.moddata, self)
        rtype.parse()
        common._debug("Type name @ 0x%x: %s" % (type_addr, rtype.name))

        if rtype.size == 0:
            common._info("  "*depth + "> WARNNING: empty type @ 0x%x" % type_addr)

        # parse the specific kind of data type
        if rtype.get_kind() == "Ptr":
            ptr_type = PtrType(type_addr, self, rtype)
            self.parsed_types[type_addr] = ptr_type
            ptr_type.parse()
            common._debug("  "*depth + ptr_type.name)
        elif rtype.get_kind() == "Struct":
            st_type = StructType(type_addr, self, rtype)
            self.parsed_types[type_addr] = st_type
            st_type.parse()
            common._debug("  "*depth + st_type.name)
        elif rtype.get_kind() == "Array":
            arr_type = ArrayType(type_addr, self, rtype)
            self.parsed_types[type_addr] = arr_type
            arr_type.parse()
            common._debug("  "*depth + arr_type.name)
        elif rtype.get_kind() == "Slice":
            slice_type = SliceType(type_addr, self, rtype)
            self.parsed_types[type_addr] = slice_type
            slice_type.parse()
            common._debug("  "*depth + slice_type.name)
        elif rtype.get_kind() == "Interface":
            itype = InterfaceType(type_addr, self, rtype)
            self.parsed_types[type_addr] = itype
            itype.parse()
            common._debug("  "*depth + itype.name)
        elif rtype.get_kind() == "Chan":
            ch_type = ChanType(type_addr, self, rtype)
            self.parsed_types[type_addr] = ch_type
            ch_type.parse()
            common._debug("  "*depth + ch_type.name)
        elif rtype.get_kind() == "Func":
            func_type = FuncType(type_addr, self, rtype)
            self.parsed_types[type_addr] = func_type
            func_type.parse()
            common._debug("  "*depth + func_type.name)
        elif rtype.get_kind() == "Map":
            map_type = MapType(type_addr, self, rtype)
            self.parsed_types[type_addr] = map_type
            map_type.parse()
            common._debug("  "*depth + map_type.name)
        elif self.is_raw_type(rtype.get_kind()):
            self.parsed_types[type_addr] = RawType(type_addr, rtype)
            common._debug("  "*depth + rtype.name)
        else:
          raise Exception('Unknown type (kind:%s)' % rtype.get_kind())

        # process uncommon type, i.e. types with mothods
        # if rtype.get_kind() != "Map" and rtype.is_uncomm():
        if rtype.is_uncomm():
            prim_type = self.parsed_types[type_addr]
            uncomm_type = UncommonType(prim_type, self)
            self.parsed_types[type_addr] = uncomm_type
            uncomm_type.parse()

        return rtype

    def has_been_parsed(self, addr):
        return (addr in self.parsed_types.keys())
    
    def eraser(self):
        cnt = 0
        for str_addr, str_len in self.types_str_info:
            # common._debug(f"{cnt}")
            cnt += 1
            try:
                ida_bytes.patch_bytes(str_addr, str_len * b"\x00")
                ida_auto.auto_wait()
            except:
                print(f"strange addr {hex(str_addr)}!")
        common._debug(f"remove {len(self.types_str_info)} strs!")




class RType():
    '''
    // rtype is the common implementation of most values.
    // It is embedded in other struct types.
    //
    // rtype must be kept in sync with ../runtime/type.go:/^type._type.
    type rtype struct {
    	size       uintptr
    	ptrdata    uintptr // number of bytes in the type that can contain pointers
    	hash       uint32  // hash of type; avoids computation in hash tables
    	tflag      tflag   // extra type information flags
    	align      uint8   // alignment of variable with this type
    	fieldAlign uint8   // alignment of struct field with this type
    	kind       uint8   // enumeration for C
    	// function for comparing objects of this type
    	// (ptr to object A, ptr to object B) -> ==?
    	equal     func(unsafe.Pointer, unsafe.Pointer) bool
    	gcdata    *byte   // garbage collection data
    	str       nameOff // string form
    	ptrToThis typeOff // type for pointer to this type, may be zero
    }
    '''
    # Refer: https://golang.org/pkg/reflect/#Kind
    TYPE_KINDS = ['Invalid Kind','Bool','Int','Int8','Int16','Int32','Int64','Uint','Uint8','Uint16','Uint32','Uint64','Uintptr','Float32','Float64','Complex64','Complex128','Array','Chan','Func','Interface','Map','Ptr','Slice','String','Struct','UnsafePointer']

    # see https://golang.org/src/reflect/type.go for constants definition
    TFLAG_UNCOMM        = 0x1
    TFLAG_STARPREFIX    = 0x2
    TFLAG_NAMED         = 0x4
    KIND_DIRECT_IFACE   = 1 << 5
    KIND_GCPROG         = 1 << 6 # Type.gc points to GC program
    KIND_MASK           = (1 << 5) - 1

    def __init__(self, addr, firstmoduledata : ModuleData, type_parser : TypesParser):
        self.addr = addr
        self.moddata = firstmoduledata
        self.type_parser = type_parser
        self.size = 0
        self.ptrdata = 0
        self.hash = None
        self.tflag = None
        self.align = 0
        self.field_align = 0
        self.kind = 0
        self.alg = None
        self.gcdata = None
        self.name_off = 0
        self.name_addr = idc.BADADDR
        self.name_obj = None
        self.name = ""
        self.ptrtothis = None
        self.ptrtothis_off = 0
        self.ptrtothis_addr = idc.BADADDR
        self.self_size = 0x20 if ADDR_SZ == 4 else 0x30

    def parse(self):
        common._debug("RType @ 0x%x" % self.addr)
        self.size = idc.get_qword(self.addr)
        idc.set_cmt(self.addr, "size", True)
        ida_bytes.create_qword(self.addr, 8)

        self.ptrdata = idc.get_qword(self.addr + ADDR_SZ)
        idc.set_cmt(self.addr + ADDR_SZ, "ptrdata", True)
        ida_bytes.create_qword(self.addr + ADDR_SZ, 8)

        self.hash = idc.get_wide_dword(self.addr + 2 * ADDR_SZ)
        idc.set_cmt(self.addr + 2 * ADDR_SZ, "hash", True)
        ida_bytes.create_dword(self.addr + ADDR_SZ * 2, 4)

        next_base_addr = self.addr + 2 * ADDR_SZ + 4
        self.tflag = idc.get_wide_byte(next_base_addr)
        ida_bytes.create_byte(next_base_addr, 1)
        
        self.align = idc.get_wide_byte(next_base_addr + 1)
        idc.set_cmt(next_base_addr + 1, "align", True)    
        ida_bytes.create_byte(next_base_addr + 1, 1)   

        self.field_align = idc.get_wide_byte(next_base_addr + 2)
        idc.set_cmt(next_base_addr + 2, "field_align", True)    
        ida_bytes.create_byte(next_base_addr + 2, 1)

        self.kind = idc.get_wide_byte(next_base_addr + 3) & RType.KIND_MASK
        idc.set_cmt(next_base_addr + 3, "kind", True)    
        ida_bytes.create_byte(next_base_addr + 3, 1)   

        next_base_addr =next_base_addr + 4
        self.alg = idc.get_qword(next_base_addr)
        idc.set_cmt(next_base_addr, "alg", True)
        idc.create_qword(next_base_addr)

        self.gcdata = idc.get_qword(next_base_addr + ADDR_SZ)
        idc.set_cmt(next_base_addr + ADDR_SZ, "gcdata", True)
        idc.create_qword(next_base_addr + ADDR_SZ)

        self.name_off = idc.get_wide_dword(next_base_addr + ADDR_SZ * 2)
        idc.create_dword(next_base_addr + ADDR_SZ * 2)
        self.name_addr = (self.moddata.types_addr + self.name_off)

        self.ptrtothis_off = idc.get_wide_dword(next_base_addr + ADDR_SZ * 2 + 4)
        idc.create_dword(next_base_addr + ADDR_SZ * 2 + 4)
        if self.ptrtothis_off > 0:
            self.ptrtothis_addr = (self.moddata.types_addr + self.ptrtothis_off) & 0xFFFFFFFF

        tflag_comm = "tflag:"
        if self.has_star_prefix():
            tflag_comm += " Star Prefix;"
        if self.is_named():
            tflag_comm += " Named;"
        if self.is_uncomm():
            tflag_comm += " Uncommon"

        idc.set_cmt(self.addr + ADDR_SZ * 2 + 4, tflag_comm, True)
        common._debug(tflag_comm)
        common._debug("kind: %s" % self.get_kind())

        if self.ptrtothis_off > 0:
            idc.set_cmt(self.addr + ADDR_SZ * 5 + 4, "ptrtothis addr: 0x%x" % self.ptrtothis_addr, True)
            common._debug("ptrtothis addr: 0x%x" % self.ptrtothis_addr)
        else:
            idc.set_cmt(self.addr + ADDR_SZ * 5 + 4, "ptrtothis addr", True)
        ida_auto.auto_wait()

        self.name_obj = Name(self.name_addr, self.moddata)
        self.name_obj.parse(self.has_star_prefix())
        self.name = self.name_obj.simple_name

        idc.set_cmt(self.addr + ADDR_SZ * 5, "name(@ 0x%x ): %s" % (self.name_addr, self.name_obj.orig_name_str), True)
        common._debug("name(@ 0x%x ): %s" % (self.name_addr, self.name_obj.orig_name_str))

        # if a raw type is un-named, and name string is erased, the name it as it's kind string
        if len(self.name) == 0 and self.type_parser.is_raw_type(self.get_kind()) and not self.is_named():
            self.name = self.get_kind()

        # if an un-raw type is named, then concat a kind string as suffix with it's name
        if len(self.name) > 0 and self.is_named() and not self.type_parser.is_raw_type(self.get_kind()):
            self.name += ("_%s" % self.get_kind().lower())

        if self.get_kind() == "Struct" and not self.is_named(): # un-named struct type
            self.name = "_struct_"

        if self.get_kind() == "Func" and not self.is_named(): # un-named func type
            self.name = "_func_"

        if self.get_kind() == "Ptr":
            self.name += "_ptr"

        if len(self.name) > 0:
            idc.set_name(self.addr, self.name, flags=idaapi.SN_FORCE)
            ida_auto.auto_wait()

        # parse type   pointer
        if self.ptrtothis_off > 0 and self.ptrtothis_addr != idc.BADADDR:
            if self.type_parser.has_been_parsed(self.ptrtothis_addr):
                self.ptrtothis = self.type_parser.parsed_types[self.ptrtothis_addr]
            else:
                # cache_parse_types.append(self.ptrtothis_addr)
                # self.ptrtothis = self.type_parser.parse_type(type_addr=self.ptrtothis_addr)
                pass
            ida_auto.auto_wait()

    def get_kind(self):
        if self.kind >= len(self.TYPE_KINDS):
            return self.TYPE_KINDS[0]
        return self.TYPE_KINDS[self.kind]

    def has_star_prefix(self):
        return self.tflag & RType.TFLAG_STARPREFIX != 0

    def is_named(self):
        return self.tflag & RType.TFLAG_NAMED != 0

    def is_uncomm(self):
        return self.tflag & RType.TFLAG_UNCOMM != 0

    def get_name(self):
        return self.name.simple_name

    def __str__(self):
        return self.get_name()



class Name():
    '''
    A rtype name struct
    Refer: https://golang.org/src/reflect/type.go
    name is an encoded type name with optional extra data.
    
    The first byte is a bit field containing:
    
        1<<0 the name is exported
        1<<1 tag data follows the name
        1<<2 pkgPath nameOff follows the name and tag
    
    The next two bytes are the data length:
    
         l := uint16(data[1])<<8 | uint16(data[2])
    
    Bytes [3:3+l] are the string data.
    
    If tag data follows then bytes 3+l and 3+l+1 are the tag length,
    with the data following.
    
    If the import path follows, then 4 bytes at the end of
    the data form a nameOff. The import path is only set for concrete
    methods that are defined in a different package than their type.
    
    If a name starts with "*", then the exported bit represents
    whether the pointed to type is exported.
    
    type name struct {
        bytes *byte
    }
    '''
    EXPORTED = 0x1
    FOLLOWED_BY_TAG = 0x2
    FOLLOWED_BY_PKGPATH = 0x4

    def __init__(self, addr, moddata : ModuleData):
        self.addr = addr
        self.moddata = moddata
        self.len = 0
        self.is_exported = None
        self.is_followed_by_tag = None
        self.is_followed_by_pkgpath = None
        self.orig_name_str = ""
        self.name_str = ""
        self.simple_name = ""
        self.full_name = ""
        self.pkg = ""
        self.pkg_len = 0
        self.tag = ""
        self.tag_len = 0
        self.name_str_addr = 0
        self.tag_addr = 0

    def parse(self, has_star_prefix):
        flag_byte = idc.get_wide_byte(self.addr)
        idc.create_byte(self.addr)
        self.is_exported = flag_byte & self.EXPORTED != 0
        self.is_followed_by_tag = flag_byte & self.FOLLOWED_BY_TAG != 0
        self.is_followed_by_pkgpath = flag_byte & self.FOLLOWED_BY_PKGPATH != 0

        self.len = ((idc.get_wide_byte(self.addr + 1) & 0xFF << 8) | (idc.get_wide_byte(self.addr + 2) & 0xFF)) & 0xFFFF
        idc.create_byte(self.addr + 1)
        idc.create_byte(self.addr + 2)
        self.orig_name_str = idc.get_bytes(self.addr + 3, self.len).decode("iso8859")
        idc.create_strlit(self.addr + 3, self.addr + 3 + self.len)
        self.name_str_addr = self.addr + 3
        self.name_str_len = self.len
        self.name_str = self.orig_name_str
        # delete star_prefix:
        while True:
            if self.name_str[0] == '*':
                self.name_str = self.name_str[1:]
            else:
                break

        if self.is_followed_by_tag:
            self.tag_len = (idc.get_wide_byte(self.addr+ 3 + self.len) & 0xFF << 8) \
                | (idc.get_wide_byte(self.addr + 3 + self.len + 1) & 0xFF)
            idc.create_byte(self.addr + 3 + self.len)
            idc.create_byte(self.addr + 3 + self.len + 1)
            self.tag = idc.get_bytes(self.addr + 3 + self.len + 2, self.tag_len).decode("iso8859")
            idc.create_strlit(self.addr + 3 + self.len + 2, self.addr + 3 + self.len + 2 + self.tag_len)
            self.tag_addr = self.addr + 3 + self.len + 2
            self.tag_len = self.tag_len
            

        # if name was reased, the replace name string with tag string
        if (not self.name_str or len(self.name_str) == 0) and self.tag and self.tag_len > 0:
            self.name_str = self.tag
            self.len = self.tag_len

        if self.is_followed_by_pkgpath:
            pkgpath_off_addr = self.addr + 3 + self.len
            if self.is_followed_by_tag:
                pkgpath_off_addr += (self.tag_len + 2)
            pkgpath_off = idc.get_wide_dword(idc.get_wide_dword(pkgpath_off_addr) & 0xFFFFFFFF)
            idc.create_dword(pkgpath_off_addr)
            if pkgpath_off > 0:
                pkgpath_addr = self.moddata.types_addr + pkgpath_off
                if pkgpath_addr == self.addr:
                    return None
                pkgpath_name_obj = Name(pkgpath_addr, self.moddata)
                if pkgpath_name_obj:
                    pkgpath_name_obj.parse(False)
                    self.pkg = pkgpath_name_obj.name_str
                    self.pkg_len = len(self.pkg)

                    if self.pkg_len:
                        idc.set_cmt(pkgpath_off_addr, "pkgpath(@ 0x%x): %s" % (pkgpath_addr, self.pkg), True)
                        ida_auto.auto_wait()
                else:
                    self.is_followed_by_pkgpath = 0

        self.full_name = "%s%s%s" % (self.pkg if self.pkg else "", ("_%s" % self.name_str) \
            if self.pkg else self.name_str, ('_%s' % self.tag) if self.tag else "")
        self.simple_name = "%s%s" % (self.pkg if self.pkg else "", ("_%s" % self.name_str) \
            if self.pkg else self.name_str)

        flag_comm_str = "flag: "
        if self.is_exported:
            flag_comm_str += "exported"
        if self.is_followed_by_tag:
            if self.is_exported:
                flag_comm_str += ", followed by tag"
            else:
                flag_comm_str += "followed by tag"
        if self.is_followed_by_pkgpath:
            if self.is_exported or self.is_followed_by_tag:
                flag_comm_str += ", followed by pkgpath"
            else:
                flag_comm_str += "followed by pkgpath"
        if len(flag_comm_str) > 6: # has valid flag
            idc.set_cmt(self.addr, flag_comm_str, True)
            ida_auto.auto_wait()

        ida_bytes.create_strlit(self.addr + 3, self.len, ida_nalt.STRTYPE_C)
        ida_auto.auto_wait()
        if self.is_followed_by_tag:
            ida_bytes.create_strlit(self.addr + 3 + self.len + 2, self.tag_len, ida_nalt.STRTYPE_C)
            idc.set_cmt(self.addr + 3 + self.len + 2, "tag of @ 0x%x" % self.addr, True)
            ida_auto.auto_wait()


class PtrType():
    '''
    Pointer type
    Refer: https://golang.org/src/reflect/type.go
    type ptrType struct {
        rtype
        elem *rtype // pointer element (pointed at) type
    }
    '''
    def __init__(self, addr, type_parser : TypesParser, rtype : RType):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.size = rtype.self_size + ADDR_SZ
        self.target_type_addr = idc.BADADDR
        self.target_rtype = None
        self.target_rtype_origname = ""
        self.name = ""

    def parse(self):
        common._debug("PtrType @ 0x%x" % self.addr)
        self.target_type_addr = idc.get_qword(self.addr + self.rtype.self_size)
        idc.create_qword(self.addr + self.rtype.self_size)
        if self.type_parser.has_been_parsed(self.target_type_addr):
            self.target_rtype = self.type_parser.parsed_types[self.target_type_addr]
            self.target_rtype_origname = self.target_rtype.rtype.name_obj.orig_name_str
        else:
            self.target_rtype = self.type_parser.parse_type(type_addr=self.target_type_addr)
            # cache_parse_types.append(self.target_type_addr)
            # return
        if not self.target_rtype:
            return
        self.target_rtype_origname = self.target_rtype.name_obj.orig_name_str
        self.name = self.target_rtype.name + "_ptr"
        idc.set_cmt(self.addr + self.rtype.self_size, "target rtype: %s" % self.target_rtype_origname, True)
        ida_auto.auto_wait()
        common._debug("target rtype: %s" % self.target_rtype_origname)

    def __str__(self):
        return self.name


class StructType():
    '''
    Struct type    
    Refer: https://golang.org/src/reflect/type.go
    type structType struct {
        rtype
        pkgPath name          // !! pointer
        fields  []structField // sorted by offset
    }
    '''
    def __init__(self, addr, type_parser : TypesParser, rtype : RType):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.size = self.rtype.self_size + 4 * ADDR_SZ
        self.fields = list()
        self.pkg_path_addr = idc.BADADDR
        self.pkg_path_obj = None
        self.pkg_path = ""
        self.name = rtype.name

    def parse(self):
        common._debug("Struct Type @ 0x%x" % self.addr)
        # parse pkg path
        self.pkg_path_addr = idc.get_qword(self.addr + self.rtype.self_size)
        idc.create_qword(self.addr + self.rtype.self_size)
        if self.pkg_path_addr > 0 and self.pkg_path_addr != idc.BADADDR:
            self.pkg_path_obj = Name(self.pkg_path_addr, self.type_parser.moddata)
            self.pkg_path_obj.parse(False)
            self.pkg_path = self.pkg_path_obj.simple_name

        # parse fields
        fields_start_addr = idc.get_qword(self.addr + self.rtype.self_size + ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + ADDR_SZ)
        fields_cnt = idc.get_qword(self.addr + self.rtype.self_size + 2 * ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + 2 * ADDR_SZ)
        fields_cap = idc.get_qword(self.addr + self.rtype.self_size + 3 * ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + 3 * ADDR_SZ)
        for idx in range(fields_cnt):
            field = StructFiled(fields_start_addr + idx * 3 * ADDR_SZ, self.type_parser)
            field.parse()
            self.fields.append(field)

        idc.set_cmt(self.addr + self.rtype.self_size, "pkg path%s" % (("(@ 0x%x): %s" % (self.pkg_path_addr, self.pkg_path)) if (self.pkg_path_addr>0 and len(self.pkg_path)>0) else ""), True)
        idc.set_cmt(self.addr + self.rtype.self_size + 2 * ADDR_SZ, "fields count: 0x%x" % fields_cnt, True)
        idc.set_cmt(self.addr + self.rtype.self_size + 3 * ADDR_SZ, "fileds capacity: 0x%x" % fields_cap, True)
        ida_auto.auto_wait()
        common._debug("Struct pkg path: %s" % (("(@ 0x%x): %s" % (self.pkg_path_addr, self.pkg_path)) if (self.pkg_path_addr>0 and len(self.pkg_path)>0) else ""))
        common._debug("Struct fields num: 0x%x" % fields_cnt)

        if len(self.rtype.name) > 0 and fields_cnt > 0:
            idc.set_cmt(self.addr + self.rtype.self_size + ADDR_SZ, "fields start address", True)
            idc.set_name(fields_start_addr, "%s_fields" % self.rtype.name, flags=idaapi.SN_FORCE)
            ida_auto.auto_wait()
            common._debug("Struct fields start addr: 0x%x" % fields_start_addr)

    def __str__(self):
        if self.rtype:
            ret_str = "> Struct: %s ( %d fields)\n" % (self.rtype.name, len(self.fields))
            for f in self.fields:
                ret_str += "\t\t- %s\n" % f
            return ret_str
        else:
            return ""



class StructFiled():
    '''
    Struct filed    
    Refer: https://golang.org/src/reflect/type.go
    type structField struct {
        name        name    // name is always non-empty
        typ         *rtype  // type of field
        offsetEmbed uintptr // byte offset of field<<1 | isEmbedded
    }
    '''
    def __init__(self, addr, type_parser : TypesParser):
        self.addr = addr
        self.type_parser = type_parser
        self.name_obj_addr = idc.BADADDR
        self.name_obj = None
        self.name = ""
        self.rtype_addr = idc.BADADDR
        self.rtype = None
        self.offset = 0
        self.is_embeded = False
        self.size = 3 * ADDR_SZ

    def parse(self):
        self.name_obj_addr = idc.get_qword(self.addr)
        idc.create_qword(self.addr)
        if self.name_obj_addr == 0 or self.name_obj_addr == idc.BADADDR:
            raise Exception("Invalid name address when parsing struct field @ 0x%x" % self.addr)
        self.name_obj = Name(self.name_obj_addr, self.type_parser.moddata)
        self.name_obj.parse(False)
        self.name = self.name_obj.simple_name

        self.rtype_addr = idc.get_qword(self.addr + ADDR_SZ)
        idc.create_qword(self.addr + ADDR_SZ)
        if self.rtype_addr == 0 or self.rtype_addr == idc.BADADDR:
            raise Exception("Invalid rtype address when parsing struct field @ 0x%x" % self.addr)
        if self.type_parser.has_been_parsed(self.rtype_addr):
            self.rtype = self.type_parser.parsed_types[self.rtype_addr]
        else:
            self.rtype = self.type_parser.parse_type(type_addr=self.rtype_addr)
            cache_parse_types.append(self.rtype_addr)
            # self.rtype = None

        off_embeded = idc.get_qword(self.addr + 2*ADDR_SZ)
        idc.create_qword(self.addr + 2 * ADDR_SZ)
        self.offset = off_embeded >> 1
        self.is_embeded = (off_embeded & 1) != 0

        idc.set_cmt(self.addr, "field name: %s" % self.name_obj.name_str, True)
        ida_auto.auto_wait()
        if self.rtype:
            idc.set_cmt(self.addr + ADDR_SZ, "field rtype: %s" % self.rtype.name, True)
            common._debug("Struct field rtype: %s" % self.rtype.name)
        ida_auto.auto_wait()
        common._debug("Struct field name: %s" % self.name_obj.name_str)
        

    def __str__(self):
        return self.name


class ArrayType():
    '''
    Array type  
    Refer: https://golang.org/src/reflect/type.go
    type arrayType struct {
        rtype
        elem  *rtype // array element type
        slice *rtype // slice type
        len   uintptr
    }
    '''
    def __init__(self, addr, type_parser : TypesParser, rtype: RType):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.name = rtype.name
        self.size = rtype.self_size + 3 * ADDR_SZ
        self.elem_type = None
        self.slice_type = None
        self.len = 0

    def parse(self):
        common._debug("Array Type @ 0x%x" % self.addr)
        elem_type_addr = idc.get_qword(self.addr + self.rtype.self_size)
        idc.create_qword(self.addr + self.rtype.self_size)
        if self.type_parser.has_been_parsed(elem_type_addr):
            self.elem_type = self.type_parser.parsed_types[elem_type_addr]
        else:
            self.elem_type = self.type_parser.parse_type(type_addr=elem_type_addr)
            # cache_parse_types.append(elem_type_addr)
            # self.elem_type = None
        if not self.elem_type:
            return
        slice_type_addr = idc.get_qword(self.addr + self.rtype.self_size + ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + ADDR_SZ)
        if self.type_parser.has_been_parsed(slice_type_addr):
            self.slice_type = self.type_parser.parsed_types[slice_type_addr]
        else:
            self.slice_type = self.type_parser.parse_type(type_addr=slice_type_addr)
            # cache_parse_types.append(slice_type_addr)
            # self.slice_type = None
        if not self.slice_type:
            return
        self.len = idc.get_qword(self.addr + self.rtype.self_size + 2 * ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + 2 * ADDR_SZ)
        idc.set_cmt(self.addr + self.rtype.self_size, "elem type: %s" % self.elem_type.name, True)
        idc.set_cmt(self.addr + self.rtype.self_size + ADDR_SZ, "slice type: %s" % self.slice_type.name, True)
        idc.set_cmt(self.addr + self.rtype.self_size + 2 * ADDR_SZ, "array length: %d" % self.len, True)
        idc.set_name(self.addr, "%s_array" % self.elem_type.name, flags=idaapi.SN_FORCE)
        ida_auto.auto_wait()
        common._debug("Array elem type: %s" % self.elem_type.name)
        common._debug("Array slice type: %s" % self.slice_type.name)

    def __str__(self):
        return "%s array(len: %d)" % (self.elem_type.name, self.len)


class SliceType():
    '''
    Slice type
    Refer: https://golang.org/src/reflect/type.go
    type sliceType struct {
        rtype
        elem *rtype // slice element type
    }
    '''
    def __init__(self, addr, type_parser : TypesParser, rtype : RType):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.name = rtype.name
        self.size = self.rtype.self_size + ADDR_SZ

    def parse(self):
        common._debug("Slice Type @ 0x%x" % self.addr)
        self.elem_type_addr = idc.get_qword(self.addr + self.rtype.self_size)
        idc.create_qword(self.addr + self.rtype.self_size)
        if self.type_parser.has_been_parsed(self.elem_type_addr):
            self.elem_rtype = self.type_parser.parsed_types[self.elem_type_addr]
        else:
            self.elem_rtype = self.type_parser.parse_type(type_addr=self.elem_type_addr)
            # cache_parse_types.append(self.elem_type_addr)
            # self.elem_rtype = None
        if self.elem_rtype:
            idc.set_cmt(self.addr + self.rtype.self_size, "elem rtype: %s" % self.elem_rtype.name, True)
            idc.set_name(self.addr, "%s_slice" % self.elem_rtype.name, flags=idaapi.SN_FORCE)
            ida_auto.auto_wait()
            common._debug("Slice elem rtype: %s" % self.elem_rtype.name)

    def __str__(self):
        if self.elem_rtype:
            return "Slice %s" % self.elem_rtype.name
        else:
            return ""


class InterfaceType():
    '''
    Interface type   
    Refer: https://golang.org/src/reflect/type.go
    type interfaceType struct {
        rtype
        pkgPath name      // import path
        methods []imethod // sorted by hash
    }
    '''
    def __init__(self, addr, type_parser : TypesParser, rtype: RType):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.size = rtype.self_size + 4*ADDR_SZ
        self.pkg_path_addr = idc.BADADDR
        self.pkg_path_obj = None
        self.pkg_path = ""
        self.name = rtype.name
        self.methods = list()

    def parse(self):
        common._debug("Interface @ 0x%x" % self.addr)
        # parse pkg path
        self.pkg_path_addr = idc.get_qword(self.addr + self.rtype.self_size)
        idc.create_qword(self.addr + self.rtype.self_size)
        if self.pkg_path_addr > 0 and self.pkg_path_addr != idc.BADADDR:
            self.pkg_path_obj = Name(self.pkg_path_addr, self.type_parser.moddata)
            self.pkg_path_obj.parse(False)
            self.pkg_path = self.pkg_path_obj.name_str

        # parse fields
        methods_start_addr = idc.get_qword(self.addr + self.rtype.self_size + ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + ADDR_SZ)
        methods_cnt = idc.get_qword(self.addr + self.rtype.self_size + 2*ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + 2 * ADDR_SZ)
        methods_cap = idc.get_qword(self.addr + self.rtype.self_size + 3*ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + 3 * ADDR_SZ)
        for idx in range(methods_cnt):
            imeth = IMethodType(methods_start_addr + idx*2*4, self.type_parser)
            imeth.parse()
            self.methods.append(imeth)

        idc.set_cmt(self.addr + self.rtype.self_size, "pkg path%s" % (("(@ 0x%x): %s" % (self.pkg_path_addr, self.pkg_path)) if (self.pkg_path_addr>0 and len(self.pkg_path)>0) else ""), True)
        idc.set_cmt(self.addr + self.rtype.self_size + 2*ADDR_SZ, "methods count: 0x%x" % methods_cnt, True)
        idc.set_cmt(self.addr + self.rtype.self_size + 3*ADDR_SZ, "methods capacity: 0x%x" % methods_cap, True)
        ida_auto.auto_wait()

        common._debug("Interface pkg path%s" % (("(@ 0x%x): %s" % (self.pkg_path_addr, self.pkg_path)) if (self.pkg_path_addr>0 and len(self.pkg_path)>0) else ""))
        common._debug("Interface methods count: 0x%x" % methods_cnt)

        if len(self.rtype.name) > 0:
            idc.set_name(methods_start_addr, "%s_methods" % self.rtype.name, flags=idaapi.SN_FORCE)
            ida_auto.auto_wait()

    def __str__(self):
        if self.rtype:
            ret_str = "> Interface: %s ( %d methods)\n" % (self.rtype.name, len(self.methods))
            for m in self.methods:
                ret_str += "\t\t- %s\n" % m
            return ret_str
        else:
            return ""


class IMethodType():
    '''
    IMethod type    
    Refer: https://golang.org/src/reflect/type.go
    type imethod struct {
        name nameOff // name of method
        typ  typeOff // .(*FuncType) underneath
    }
    '''
    def __init__(self, addr, type_parser : TypesParser):
        self.addr = addr
        self.type_parser = type_parser
        self.types_addr = type_parser.moddata.types_addr
        self.size = 8
        self.name_obj = None
        self.name = ""
        self.type = None

    def parse(self):
        common._debug("Imethod Type @ 0x%x" % self.addr)
        name_off = idc.get_wide_dword(self.addr)
        idc.create_dword(self.addr)
        name_addr = (self.types_addr + name_off) & 0xFFFFFFFF
        self.name_obj = Name(name_addr, self.type_parser.moddata)
        self.name_obj.parse(False)
        self.name = self.name_obj.simple_name

        type_off = idc.get_wide_dword(self.addr + 4)
        idc.create_dword(self.addr + 4)
        type_addr = (self.types_addr + type_off) & 0xFFFFFFFF
        if type_off > 0 and type_addr != idc.BADADDR:
            if self.type_parser.has_been_parsed(type_addr):
                self.type = self.type_parser.parsed_types[type_addr].rtype
            else:
                self.type = self.type_parser.parse_type(type_addr=type_addr)
                # cache_parse_types.append(type_addr)
                # self.type = None

        if name_off > 0 and name_off != idc.BADADDR:
            idc.set_cmt(self.addr, "imethod name(@ 0x%x): %s" % (name_addr, self.name), True)
            ida_auto.auto_wait()
            common._debug("Interface imethod name(@ 0x%x): %s" % (name_addr, self.name))

        if type_off > 0 and type_addr != idc.BADADDR and self.type:
            idc.set_cmt(self.addr + 4, "imethod type(@ 0x%x): %s" % (type_addr, self.type.name_obj.name_str), True)
            ida_auto.auto_wait()
            common._debug("Interface imethod type(@ 0x%x): %s" % (type_addr, self.type.name_obj.name_str))

    def __str__(self):
        if self.name:
            return self.name_obj.full_name
        else:
            return ""


class ChanType():
    '''
    Channel type    
    Refer: https://golang.org/src/reflect/type.go
    type chanType struct {
        rtype
        elem *rtype  // channel element type
        dir  uintptr // channel direction (ChanDir)
    }
    '''
    RECV_DIR = 1
    SEND_DIR = 2
    BOTH_DIR = 3

    def __init__(self, addr, type_parser : TypesParser, rtype : RType):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.size = self.rtype.self_size + 2 * ADDR_SZ
        self.direction = ""
        self.name = ""

    def parse(self):
        common._debug("Channel Type @ 0x%x" % self.addr)
        elem_type_addr = idc.get_qword(self.addr + self.rtype.self_size)
        idc.create_qword(self.addr + self.rtype.self_size)
        if self.type_parser.has_been_parsed(elem_type_addr):
            self.elem_type = self.type_parser.parsed_types[elem_type_addr]
        else:
            self.elem_type = self.type_parser.parse_type(type_addr=elem_type_addr)
            # cache_parse_types.append(elem_type_addr)
            # self.elem_type = None
        if not self.elem_type:
            return
        self.elem_type.parse()
        dir_code = idc.get_qword(self.addr + self.rtype.self_size + ADDR_SZ)
        idc.create_qword(self.addr + self.rtype.self_size + ADDR_SZ)
        self.direction = self.get_direction(dir_code)

        self.name = "channel %s (direction: %s)" % (self.rtype.name, self.direction)

        idc.set_cmt(self.addr + self.rtype.self_size, "elem type: %s" % self.elem_type.name, True)
        idc.set_cmt(self.addr + self.rtype.self_size + ADDR_SZ, "chan direction: %s" % self.direction, True)
        ida_auto.auto_wait()

    def get_direction(self, dir_code):
        if dir_code == self.RECV_DIR:
          return 'recv'
        elif dir_code == self.SEND_DIR:
          return 'send'
        else:
          return 'send & recv'

    def __str__(self):
        return self.name


class FuncType():
    '''
    Function Type
    Refer: https://golang.org/src/reflect/type.go
    type funcType struct {
        rtype
        inCount  uint16
        outCount uint16 // top bit is set if last input parameter is ...
        padding  uint32 // ! only on some architectures (e.g. x64)
    }
    Note: "A *rtype for each in and out parameter is stored in an array that
    directly follows the funcType (and possibly its uncommonType)."
    '''
    VARIADIC_FLAG = 0x8000
    def __init__(self, addr, type_parser : TypesParser, rtype : RType):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.para_cnt = 0
        self.ret_cnt = 0
        self.padding = -1
        self.is_variadic = False
        self.para_types = list()
        self.para_type_addrs = list()
        self.ret_types = list()
        self.ret_type_addrs = list()
        self.name = rtype.name
        self.size = rtype.self_size + 2*2 # without padding

    def parse(self):
        common._debug("Func Type @ 0x%x" % self.addr)
        self.para_cnt = idc.get_wide_word(self.addr + self.rtype.self_size)
        idc.create_word(self.addr + self.rtype.self_size)
        self.ret_cnt = idc.get_wide_word(self.addr + self.rtype.self_size + 2) 
        idc.create_word(self.addr + self.rtype.self_size + 2)
        if self.ret_cnt & FuncType.VARIADIC_FLAG:
            self.is_variadic = True
            self.ret_cnt = self.ret_cnt & 0x7FFF
        self.padding = idc.get_wide_dword(self.addr + self.rtype.self_size + 4)
        idc.create_dword(self.addr + self.rtype.self_size + 4)
        if self.padding == 0: # skip padding if present
            self.size += 4
        curr_addr = self.addr + self.size
        if self.rtype.is_uncomm():
            curr_addr += UncommonType.SIZE

        for in_idx in range(self.para_cnt):
            curr_para_type = None
            curr_para_type_off = curr_addr + in_idx*ADDR_SZ
            para_type_addr = idc.get_qword(curr_para_type_off)
            idc.create_qword(curr_para_type_off)
            self.para_type_addrs.append(para_type_addr)
            if self.type_parser.has_been_parsed(para_type_addr):
                curr_para_type = self.type_parser.parsed_types[para_type_addr]
            else:
                curr_para_type = self.type_parser.parse_type(type_addr=para_type_addr)
                # cache_parse_types.append(para_type_addr)
                # curr_para_type = None
            if not curr_para_type:
                return
            self.para_types.append(curr_para_type)
            ida_auto.auto_wait()

        curr_addr += self.para_cnt * ADDR_SZ
        for out_idx in range(self.ret_cnt):
            curr_ret_type = None
            curr_ret_type_off = curr_addr + out_idx*ADDR_SZ
            ret_type_addr = idc.get_qword(curr_ret_type_off)
            idc.create_qword(curr_ret_type_off)
            self.ret_type_addrs.append(ret_type_addr)
            if self.type_parser.has_been_parsed(ret_type_addr):
                curr_ret_type = self.type_parser.parsed_types[ret_type_addr]
            else:
                curr_ret_type = self.type_parser.parse_type(type_addr=ret_type_addr)
                # cache_parse_types.append(ret_type_addr)
                # curr_ret_type = None
            if not curr_ret_type:
                return
            self.ret_types.append(curr_ret_type)
            ida_auto.auto_wait()

        idc.set_cmt(self.addr + self.rtype.self_size, "Parameter count: %d" % self.para_cnt, True)
        idc.set_cmt(self.addr + self.rtype.self_size + 2, "%s%s" % ("Flag: Varidic;" if self.ret_cnt & FuncType.VARIADIC_FLAG else "", "Return value count: %d" % self.ret_cnt), True)
        ida_auto.auto_wait()

    def __str__(self):
        return "> func %s (para: %d %s  -  return: %d)\n" % (self.rtype.name, self.para_cnt, "+ [...]" if self.is_variadic else "", self.ret_cnt)


class MapType():
    '''
    Map type
    Refer: https://golang.org/src/reflect/type.go
    type mapType struct {
        rtype
        key    *rtype // map key type
        elem   *rtype // map element (value) type
        bucket *rtype // internal bucket structure
        // function for hashing keys (ptr to key, seed) -> hash
        hasher     func(unsafe.Pointer, uintptr) uintptr // go version <1.14 has no this field
        keysize    uint8  // size of key slot
        valuesize  uint8  // size of value slot
        bucketsize uint16 // size of bucket
        flags      uint32
    }
    '''
    def __init__(self, addr, type_parser : TypesParser, rtype: RType):
        self.addr = addr
        self.type_parser = type_parser
        self.rtype = rtype
        self.key_type = None
        self.elem_type = None
        self.buck_type = None
        self.hasher_func_addr = 0
        self.key_size = 0
        self.val_size = 0
        self.buck_size = 0
        self.flags = -1
        self.name = ""
        self.go_subver = 0
        common._debug("GOVER in map struct: %s" % common.GOVER)
        if len(common.GOVER) > 0:
            self.go_subver = int(common.GOVER.split(".")[1])
            if self.go_subver >= 14:
                self.size = rtype.self_size + 4 * ADDR_SZ + 1 + 1 + 2 + 4
            else:
                self.size = rtype.self_size + 3 * ADDR_SZ + 1 + 1 + 2 + 4
        else:
            self.size = rtype.self_size + 4 * ADDR_SZ + 1 + 1 + 2 + 4

    def parse(self):
        common._debug("Map Type @ 0x%x" % self.addr)
        map_attr_addr = self.addr + self.rtype.self_size

        key_type_addr = idc.get_qword(map_attr_addr)
        idc.create_qword(map_attr_addr)
        if self.type_parser.has_been_parsed(key_type_addr):
            self.key_type = self.type_parser.parsed_types[key_type_addr]
        else:
            self.key_type = self.type_parser.parse_type(type_addr=key_type_addr)
            #cache_parse_types.append(key_type_addr)
            #self.key_type = None
        if not self.key_type:
            return
        elem_type_addr = idc.get_qword(map_attr_addr + ADDR_SZ)
        idc.create_qword(map_attr_addr + ADDR_SZ)
        if self.type_parser.has_been_parsed(elem_type_addr):
            self.elem_type = self.type_parser.parsed_types[elem_type_addr]
        else:
            self.elem_type = self.type_parser.parse_type(type_addr=elem_type_addr)
            # cache_parse_types.append(elem_type_addr)
            # self.elem_type = None
        if not self.elem_type:
            return
        buck_type_addr = idc.get_qword(map_attr_addr + 2*ADDR_SZ)
        idc.create_qword(map_attr_addr + 2 * ADDR_SZ)
        if self.type_parser.has_been_parsed(buck_type_addr):
            self.buck_type = self.type_parser.parsed_types[buck_type_addr]
        else:
            self.buck_type = self.type_parser.parse_type(type_addr=buck_type_addr)
            # cache_parse_types.append(buck_type_addr)
            # self.buck_type = None
        if not self.buck_type:
            return
        if self.go_subver < 14:
            self.key_size = idc.get_wide_byte(map_attr_addr + 3*ADDR_SZ) & 0xFF
            self.val_size =  idc.get_wide_byte(map_attr_addr + 3*ADDR_SZ + 1) & 0xFF
            self.buck_size = idc.get_wide_word(map_attr_addr + 3*ADDR_SZ + 2)
            self.flags = idc.get_wide_dword(map_attr_addr + 3*ADDR_SZ + 4)
            idc.create_byte(map_attr_addr + 3 * ADDR_SZ)
            idc.create_byte(map_attr_addr + 3 * ADDR_SZ + 1)
            idc.create_word(map_attr_addr + 3 * ADDR_SZ + 2)
            idc.create_dword(map_attr_addr + 3 * ADDR_SZ + 4)
        else:
            self.hasher_func_addr = idc.get_qword(map_attr_addr + 3*ADDR_SZ)
            self.key_size = idc.get_wide_byte(map_attr_addr + 4*ADDR_SZ)
            self.val_size = idc.get_wide_byte(map_attr_addr + 4*ADDR_SZ + 1)
            self.buck_size = idc.get_wide_word(map_attr_addr + 4*ADDR_SZ + 2)
            self.flags = idc.get_wide_dword(map_attr_addr + 4*ADDR_SZ + 4)
            idc.create_byte(map_attr_addr + 3 * ADDR_SZ)
            idc.create_byte(map_attr_addr + 3 * ADDR_SZ + 1)
            idc.create_word(map_attr_addr + 3 * ADDR_SZ + 2)
            idc.create_dword(map_attr_addr + 3 * ADDR_SZ + 4)

        self.name = "map [%s]%s" % (self.key_type.name, self.elem_type.name)

        idc.set_cmt(map_attr_addr, "Key type: %s" % self.key_type.name, True)
        idc.set_cmt(map_attr_addr + ADDR_SZ, "Elem type: %s " % self.elem_type.name, True)
        idc.set_cmt(map_attr_addr + 2*ADDR_SZ, "Bucket type: %s" % self.buck_type.name, True)
        if self.go_subver < 14:
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ, "Key size: 0x%x" % self.key_size, True)
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ + 1, "Value size: 0x%x" % self.val_size, True)
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ + 2, "Bucket size: 0x%x" % self.buck_size, True)
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ + 4, "Flags: 0x%x" % self.flags, True)
        else:
            idc.set_cmt(map_attr_addr + 3*ADDR_SZ, "hash function for hashing keys (ptr to key, seed) -> hash", True)
            idc.set_cmt(map_attr_addr + 4*ADDR_SZ, "Key size: 0x%x" % self.key_size, True)
            idc.set_cmt(map_attr_addr + 4*ADDR_SZ + 1, "Value size: 0x%x" % self.val_size, True)
            idc.set_cmt(map_attr_addr + 4*ADDR_SZ + 2, "Bucket size: 0x%x" % self.buck_size, True)
            idc.set_cmt(map_attr_addr + 4*ADDR_SZ + 4, "Flags: 0x%x" % self.flags, True)
        ida_auto.auto_wait()

        common._debug("Map Key type: %s" % self.key_type.name)
        common._debug("Map Elem type: %s " % self.elem_type.name)

    def __str__(self):
        return self.name

class UncommonType():
    '''
    Uncommon type
    Refer: https://golang.org/src/reflect/type.go
    Wrapper around primaryType to access uncommon type:
    // uncommonType is present only for defined types or types with methods
    // (if T is a defined type, the uncommonTypes for T and *T have methods).
    // Using a pointer to this struct reduces the overall size required
    // to describe a non-defined type with no methods
    type uncommonType struct {
        pkgPath nameOff // import path; empty for built-in types like int, string
        mcount  uint16  // number of methods
        xcount  uint16  // number of exported methods
        moff    uint32  // offset from this uncommontype to [mcount]method
        _       uint32  // unused
    }
    '''
    SIZE = 16

    def __init__(self, prim_type, type_parser : TypesParser):
        self.addr = prim_type.addr
        self.prim_type = prim_type
        self.type_parser = type_parser
        self.rtype = prim_type.rtype
        self.uncomm_type_addr = prim_type.addr + prim_type.size
        self.types_addr = type_parser.moddata.types_addr
        self.meth_cnt = 0
        self.xmeth_cnt = 0
        self.meth_off = 0
        self.unused = 0
        self.methods = list()
        self.pkgpath_addr = idc.BADADDR
        self.pkg_path = ""
        self.name = prim_type.name
        self.size = UncommonType.SIZE
        
    def parse(self):
        common._debug("Start to parse Uncommon type @ 0x%x , Uncommon field start addr @ 0x%x" % (self.addr, self.uncomm_type_addr))
        pkgpath_off = idc.get_wide_dword(self.uncomm_type_addr) & 0xFFFFFFFF
        idc.create_dword(self.uncomm_type_addr)
        if pkgpath_off != 0:
            self.pkgpath_addr = self.types_addr + pkgpath_off
            pkg_path_obj = Name(self.pkgpath_addr, self.type_parser.moddata)
            pkg_path_obj.parse(False)
            self.pkg_path = pkg_path_obj.name_str

        self.meth_cnt = idc.get_wide_word(self.uncomm_type_addr + 4) & 0xFFFF
        self.xmeth_cnt = idc.get_wide_word(self.uncomm_type_addr + 6) & 0xFFFF
        self.meth_off = idc.get_wide_dword(self.uncomm_type_addr + 8) & 0xFFFFFFFF
        self.unused = idc.get_wide_dword(self.uncomm_type_addr + 12) & 0xFFFFFFFF
        idc.create_word(self.uncomm_type_addr + 4)
        idc.create_word(self.uncomm_type_addr + 6)
        idc.create_dword(self.uncomm_type_addr + 8)
        idc.create_dword(self.uncomm_type_addr + 12)
        # parse method
        methods_start_addr = (self.uncomm_type_addr + self.meth_off) & 0xFFFFFFFF
        for i in range(self.meth_cnt):
            #meth_addr = self.uncomm_type_addr + i * self.size
            meth = MethodType(methods_start_addr, self.type_parser)
            meth.parse()
            self.methods.append(meth)
            methods_start_addr += meth.size

        idc.set_cmt(self.uncomm_type_addr, "pkg path%s" % (("(@ 0x%x): %s" % (self.pkgpath_addr, self.pkg_path)) if (pkgpath_off>0 and len(self.pkg_path)>0) else ""), True)
        common._debug("Ucommon type pkg path%s" % (("(@ 0x%x): %s" % (self.pkgpath_addr, self.pkg_path)) if (pkgpath_off>0 and len(self.pkg_path)>0) else ""))
        idc.set_cmt(self.uncomm_type_addr + 4, "methods number: %d" % self.meth_cnt, True)
        common._debug("Uncommon type methods number: %d" % self.meth_cnt)
        idc.set_cmt(self.uncomm_type_addr + 6, "exported methods number: %d" % self.xmeth_cnt, True)
        if self.meth_cnt > 0:
            idc.set_cmt(self.uncomm_type_addr + 8, "methods addr: 0x%x" % ((self.uncomm_type_addr + self.meth_off) & 0xFFFFFFFF), True)
            common._debug("Ucommon type methods addr: 0x%x" % ((self.uncomm_type_addr + self.meth_off) & 0xFFFFFFFF))
        else:
            idc.set_cmt(self.uncomm_type_addr + 8, "methods offset", True)
        idc.set_cmt(self.uncomm_type_addr + 12, "unused field: 0x%x" % self.unused, True)
        ida_auto.auto_wait()

    def __str__(self):
        ret_str = "%s" % self.prim_type
        if self.meth_cnt > 0:
            ret_str += "\n\t\t> %d methods:\n" % self.meth_cnt
            for meth in self.methods:
                ret_str += "\t\t - %s\n" % meth.name

        return ret_str


class MethodType():
    '''
    Method type of no-interface type
    Refer: https://golang.org/src/reflect/type.go
    type method struct {
        name nameOff // name of method
        mtyp typeOff // method type (without receiver) // offset to an *rtype
        ifn  textOff // fn used in interface call (one-word receiver) // offset from top of text section
        tfn  textOff // fn used for normal method call // offset from top of text section
    }
    '''
    def __init__(self, addr, type_parser : TypesParser):
        self.addr = addr
        self.type_parser = type_parser
        self.types_addr = type_parser.moddata.types_addr
        self.text_addr = type_parser.moddata.text_addr
        self.name_addr = idc.BADADDR
        self.name_obj = None
        self.name = ""
        self.mtype_addr = idc.BADADDR
        self.mtype = None
        self.ifn_addr = idc.BADADDR
        self.ifn_off = 0
        self.tfn_addr = idc.BADADDR
        self.tfn_off = 0
        self.size = 4*4

    def parse(self):
        name_off = idc.get_wide_dword(self.addr) & 0xFFFFFFFF
        idc.create_dword(self.addr)
        if name_off > 0:
            self.name_addr = self.types_addr + name_off
            self.name_obj = Name(self.name_addr, self.type_parser.moddata)
            self.name_obj.parse(False)
            self.name = self.name_obj.simple_name

        # note: some methods are actually not present in the binary
        # for those, typeOff, ifn, tfn are 0
        type_off = idc.get_wide_dword(self.addr + 4) & 0xFFFFFFFF
        idc.create_dword(self.addr + 4)
        if type_off > 0:
            self.mtype_addr = self.types_addr + type_off
            if self.type_parser.has_been_parsed(self.mtype_addr):
                self.mtype = self.type_parser.parsed_types[self.mtype_addr].rtype
            else:
                self.mtype = self.type_parser.parse_type(type_addr=self.mtype_addr)
                #cache_parse_types.append(self.mtype_addr)
                #self.mtype = None
        if not self.mtype:
            return
        self.ifn_off = idc.get_wide_dword(self.addr + 8) & 0xFFFFFFFF
        self.tfn_off = idc.get_wide_dword(self.addr + 12) & 0xFFFFFFFF
        idc.create_dword(self.addr + 8)
        idc.create_dword(self.addr + 12)

        idc.set_cmt(self.addr, "Method Name%s" % (("(@ 0x%x): %s" % (self.name_addr, self.name)) if (name_off>0 and len(self.name)>0) else ""), True)
        common._debug("Ucommon type Method Name%s" % (("(@ 0x%x): %s" % (self.name_addr, self.name)) if (name_off>0 and len(self.name)>0) else ""))

        idc.set_cmt(self.addr + 4, "Method Type%s" % (("(@ 0x%x): %s" % (self.mtype_addr, self.mtype.name_obj.name_str)) if (type_off>0 and self.mtype is not None) else ""), True)
        common._debug("Uncommon type Method Type%s" % (("(@ 0x%x): %s" % (self.mtype_addr, self.mtype.name_obj.name_str)) if (type_off>0 and self.mtype is not None) else ""))

        self.ifn_addr = (self.text_addr + self.ifn_off) & 0xFFFFFFFF
        ifn_name = idc.get_func_name(self.ifn_addr)
        if ifn_name is None or len(ifn_name) == 0:
            if self.mtype is not None:
                ifn_name = self.mtype.name
            else:
                ifn_name == "_func_"
        idc.set_cmt(self.addr + 8, "ifn%s" % (("(@ 0x%x): %s" % (self.ifn_addr, ifn_name)) if self.ifn_off>0 else ""), True)

        self.tfn_addr = (self.text_addr + self.tfn_off) & 0xFFFFFFFF
        tfn_name = idc.get_func_name(self.tfn_addr)
        if tfn_name is None or len(tfn_name) == 0:
            if self.mtype is not None:
                tfn_name = self.mtype.name
            else:
                tfn_name = "_func_"
        idc.set_cmt(self.addr + 12, "tfn%s" % (("(@ 0x%x): %s" % (self.tfn_addr, tfn_name)) if self.tfn_off>0 else ""), True)

        ida_auto.auto_wait()


class RawType():
    '''
    Wrapper for built-in types (contains only rtype)
    '''
    def __init__(self, addr, rtype):
        self.addr = addr
        self.rtype = rtype
        self.name = rtype.name
        self.size = rtype.self_size

    def __str__(self):
        return "> raw type: %s\n" % self.name