#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi, idautils, ida_bytes
idaapi.require("common")
idaapi.require("moduledata")
from common import ADDR_SZ
import common
from moduledata import ModuleData
import ida_nalt, ida_auto, ida_funcs

class Pclntbl():
    '''
    PcLineTable:
    Refer:
        1. golang.org/s/go12symtab
        2. https://golang.org/src/debug/gosym/pclntab.go

    For an amd64 system, the pclntab symbol begins:

        [4] 0xfffffffa
        [2] 0x00 0x00
        [1] 0x01
        [1] 0x08
        [8] N (size of function symbol table)
        [8] pc0
        [8] func0 offset
        [8] pc1
        [8] func1 offset
        …
        [8] pcN
        [4] int32 offset from start to source file table
        … and then data referred to by offset, in an unspecified order …
    '''
    # Magic number of pclinetable header
    MAGIC = 0xFFFFFFFA

    def __init__(self, start_addr, related_mod_data : ModuleData):
        self.start_addr = start_addr
        self.goroot = ""
        self.mod_data = related_mod_data
        self.func_struct = []
        self.src_file_path_dic = []

    def parse_hdr(self):
        self.pcHeader_addr = self.start_addr
        self.minLC = idc.get_wide_byte(self.pcHeader_addr + 6)
        idc.set_cmt(self.pcHeader_addr + 6, "minLC", False)
        self.ptrSize = idc.get_wide_byte(self.pcHeader_addr + 7)
        idc.set_cmt(self.pcHeader_addr + 7, "ptrSize", False)
        self.nfunc = idc.get_wide_dword(self.pcHeader_addr + 8)
        idc.set_cmt(self.pcHeader_addr + 8, "nfunc", False)
        self.nfiles = idc.get_wide_dword(self.pcHeader_addr + 8 + ADDR_SZ * 1)
        idc.set_cmt(self.pcHeader_addr + 8 + ADDR_SZ * 1, "nfiles", False)
        self.funcnameOffset = idc.get_wide_dword(self.pcHeader_addr + 8 + ADDR_SZ * 2)
        idc.set_cmt(self.pcHeader_addr + 8 + ADDR_SZ * 2, "funcnameOffset", False)
        self.cuOffset = idc.get_wide_dword(self.pcHeader_addr + 8 + ADDR_SZ * 3)
        idc.set_cmt(self.pcHeader_addr + 8 + ADDR_SZ * 3, "cuOffset", False)
        self.filetabOffset = idc.get_wide_dword(self.pcHeader_addr + 8 + ADDR_SZ * 4)
        idc.set_cmt(self.pcHeader_addr + 8 + ADDR_SZ * 4, "fileTabOffset", False)
        self.pctabOffset = idc.get_wide_dword(self.pcHeader_addr + 8 + ADDR_SZ * 5)
        idc.set_cmt(self.pcHeader_addr + 8 + ADDR_SZ * 5, "pctableOffset", False)
        self.pclnOffset = idc.get_wide_dword(self.pcHeader_addr + 8 + ADDR_SZ * 6)
        idc.set_cmt(self.pcHeader_addr + 8 + ADDR_SZ * 6, "pclnOffset", False)
        self.parsed_hdr = True        

    def parse_funcs(self):
        self.funcname_addr = self.start_addr + self.funcnameOffset
        common._debug(f'Total functions number: {self.nfunc}')
        assert self.mod_data.parsed == True
        self.func_table_addr = self.mod_data.functab
        common._debug(f'func table addr {hex(self.func_table_addr)}')
        for i in range(self.nfunc):
            try:
                func_addr = idc.get_qword(self.func_table_addr + i * ADDR_SZ * 2)
                func_struct_off = idc.get_qword(self.func_table_addr + i * ADDR_SZ * 2 + ADDR_SZ)
                func_struct_addr = self.func_table_addr + func_struct_off
                func_struct = FuncStruct(func_struct_addr)
                func_struct.parse(self.funcname_addr)
                common._debug(f"find {hex(func_addr)} name is {func_struct.name}")
                if not idc.get_func_name(func_addr):
                    common._debug("create function @ %x" % func_addr)
                    ida_bytes.del_items(func_addr, ida_bytes.DELIT_EXPAND)
                    ida_auto.auto_wait()
                    idc.create_insn(func_addr)
                    ida_auto.auto_wait()
                    if ida_funcs.add_func(func_addr):
                        ida_auto.auto_wait()
                idc.set_name(func_addr, func_struct.name.decode("iso8859"), idc.SN_NOWARN)
                self.func_struct.append(func_struct)
            except:
                continue
        self.parsed_funcs = True

    def parse_cutab_and_filetab(self):
        common._debug(f"parse all file path in executables!")
        for i in range(0, self.mod_data.cutab_num, 4):
            try:
                str_addr = idc.get_wide_dword(self.mod_data.cutab + i)
                if str_addr == 0xFFFFFFFF:
                    continue
                str_addr += self.mod_data.filetab_addr
                str_addr_len = ida_bytes.get_max_strlit_length(str_addr, ida_nalt.STRTYPE_C)
                str_of_file = ida_bytes.get_strlit_contents(str_addr, str_addr_len, ida_nalt.STRTYPE_C)
                common._debug(f"{str_of_file}")
                self.src_file_path_dic.append((str_addr, str_addr_len, self.mod_data.cutab + i))
            except:
                continue
        self.parsed_source_file_path = True

    def parse(self):
        self.parse_hdr()
        self.parse_funcs()
        self.parse_cutab_and_filetab()
    
    def eraser(self):
        assert self.parsed_funcs == True
        for item in self.func_struct:
            ida_bytes.patch_bytes(item.name_addr, b"\x00" * item.name_lenth)
            ida_bytes.patch_dword(item.start_addr + ADDR_SZ + 4 * 7, 0x0)
        common._debug(f"erase all function names and cuOffset!")

        assert self.parsed_source_file_path == True
        for str_addr, str_len, str_p_addr in self.src_file_path_dic:
            ida_bytes.patch_bytes(str_addr, b"\x00" * str_len)
            ida_bytes.patch_dword(str_p_addr, 0x0)
        common._debug(f"erase all src path str")

class FuncStruct():
    '''
    Latest version:
    Refer: https://golang.org/src/runtime/runtime2.go

    // Layout of in-memory per-function information prepared by linker
    // See https://golang.org/s/go12symtab.
    // Keep in sync with linker (../cmd/link/internal/ld/pcln.go:/pclntab)
    // and with package debug/gosym and with symtab.go in package runtime.
    type _func struct {
    	entry   uintptr // start pc
    	nameoff int32   // function name

    	args        int32  // in/out args size
    	deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.

    	pcsp      uint32
    	pcfile    uint32
    	pcln      uint32
    	npcdata   uint32
    	cuOffset  uint32  // runtime.cutab offset of this function's CU
    	funcID    funcID  // set for certain special runtime functions
    	_         [2]byte // pad
    	nfuncdata uint8   // must be last
    }
    '''
    def __init__(self, start_addr):
        self.start_addr = start_addr

    def parse(self, func_name_addr=None):
        self.entry = idc.get_qword(self.start_addr)
        self.nameoff = idc.get_wide_dword(self.start_addr + ADDR_SZ)
        self.args = idc.get_wide_dword(self.start_addr + ADDR_SZ + 4 * 1)
        self.deferreturn = idc.get_wide_dword(self.start_addr + ADDR_SZ + 4 * 2)
        self.pcsp = idc.get_wide_dword(self.start_addr + ADDR_SZ + 4 * 3)
        self.pcfile = idc.get_wide_dword(self.start_addr + ADDR_SZ + 4 * 4)  
        self.pcln = idc.get_wide_dword(self.start_addr + ADDR_SZ + 4 * 5)
        self.npcdata = idc.get_wide_dword(self.start_addr + ADDR_SZ + 4 * 6)
        self.cuOffset = idc.get_wide_dword(self.start_addr + ADDR_SZ + 4 * 7)
        self.funcID = idc.get_wide_byte(self.start_addr + ADDR_SZ + 4 * 8)
        self.nfuncdata = idc.get_wide_byte(self.start_addr + ADDR_SZ + 4 * 8 + 3)
        if func_name_addr:
            self.name_addr = func_name_addr + self.nameoff
            self.name_lenth = ida_bytes.get_max_strlit_length(self.name_addr, ida_nalt.STRTYPE_C)
            self.name = ida_bytes.get_strlit_contents(self.name_addr, self.name_lenth, ida_nalt.STRTYPE_C)
            if self.name:
                self.name = self.name.replace(b"/", b"_").replace(b".", b"_").replace(b"(", b"_").replace(b")", b"_").replace(b"*", b"_").replace(b"-", b"_")

# Function pointers are often used instead of passing a direct address to the
# function -- this function names them based off what they're currently named
# to ease reading
#
# lea     rax, main_GetExternIP_ptr <-- pointer to actual function
# mov     [rsp+1C0h+var_1B8], rax <-- loaded as arg for next function
# call    runtime_newproc <-- function is used inside a new process

def parse_func_pointer():
    pass
