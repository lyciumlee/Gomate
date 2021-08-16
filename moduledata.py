#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from ida_typeinf import FAH_BYTE
import idc, idaapi, ida_segment, ida_bytes
idaapi.require("pclntbl")
idaapi.require("common")
from common import ADDR_SZ

def is_stripped():
    '''
    Check Binary file if is stripped by find [.go.plt] segment
    '''
    goplt_seg = common.get_seg([".go.plt", "__go_plt"])
    if not goplt_seg: # None
        return True # is stripped
    return False # not stripped

def get_mdata_seg():
    seg = None

    ftype = idc.get_inf_attr(idc.INF_FILETYPE)
    if ftype == idc.FT_PE or ftype == idc.FT_EXE or ftype == idc.FT_EXE_OLD:
        seg = common.get_seg([".data"])
    else:
        seg = common.get_seg([".noptrdata", "__noptrdata"])

    if seg is None:
        # runtime.pclntab in .rdata for newer PE binary
        seg = common.get_seg_by_symname(['runtime.noptrdata'])

    if seg is None:
        raise Exception("Invalid address of segment [.noptrdata]")
    return seg


def test_firstmoduledata(possible_addr):
    '''
    Check if current addr is first module data
    '''
    mod_data = ModuleData(possible_addr)
    mod_data.parse(is_test=True)

    if mod_data.funcnametab == (mod_data.pcHeader.pcHeader_addr + mod_data.pcHeader.funcnameOffset):
        return True
    return False

def find_first_moduledata_addr_by_brute():
    magic_num = pclntbl.Pclntbl.MAGIC
    first_moduledata_addr = idc.BADADDR

    segn = ida_segment.get_segm_qty()
    for idx in range(segn):
        curr_seg = ida_segment.getnseg(idx)
        curr_addr = curr_seg.start_ea
        while curr_addr <= curr_seg.end_ea:
            if idc.get_wide_dword(idc.get_wide_dword(curr_addr)) & 0xFFFFFFFF == magic_num: # possible firstmoduledata
                if test_firstmoduledata(curr_addr):
                    break
            curr_addr += ADDR_SZ

        if curr_addr >= curr_seg.end_ea:
            continue

        first_moduledata_addr = curr_addr
        break

    return first_moduledata_addr

def find_first_moduledata_addr():
    first_moduledata_addr = idc.BADADDR

    if not is_stripped(): # not stripped, find firstmoduledata by symbol name
        common._debug("Binary file is not stripped")
        for addr, name in idautils.Names():
            if name == "runtime.firstmoduledata":
                first_moduledata_addr = addr
                break
    else: # is stripped, find firstmodule data by bruteforce searching
        common._debug("Binary file is stripped")
        magic_num = pclntbl.Pclntbl.MAGIC
        # firstmoduledata is contained in segment [.noptrdata]
        mdata_seg = get_mdata_seg()
        if mdata_seg.start_ea == 0:
            common._error("Failed to find valid segment [.noptrdata]")

        curr_addr = mdata_seg.start_ea
        while curr_addr <= mdata_seg.end_ea:
            if idc.get_wide_dword(idc.get_wide_dword(curr_addr)) & 0xFFFFFFFF == magic_num: # possible firstmoduledata
                if test_firstmoduledata(curr_addr):
                    break
            curr_addr += ADDR_SZ
        
        if curr_addr < mdata_seg.end_ea:
            first_moduledata_addr = curr_addr
        else:
            first_moduledata_addr = find_first_moduledata_addr_by_brute()

        if first_moduledata_addr == idc.BADADDR:
            raise Exception("Failed to find firstmoduledata address!")

    return first_moduledata_addr

class pcHeader():
    #  pcHeader holds data used by the pclntab lookups.
    #     type pcHeader struct {
    #         magic          uint32  // 0xFFFFFFFA
    #         pad1, pad2     uint8   // 0,0
    #         minLC          uint8   // min instruction size
    #         ptrSize        uint8   // size of a ptr in bytes
    #         nfunc          int     // number of functions in the module
    #         nfiles         uint    // number of entries in the file tab.
    #         funcnameOffset uintptr // offset to the funcnametab variable from pcHeader
    #         cuOffset       uintptr // offset to the cutab variable from pcHeader
    #         filetabOffset  uintptr // offset to the filetab variable from pcHeader
    #         pctabOffset    uintptr // offset to the pctab varible from pcHeader
    #         pclnOffset     uintptr // offset to the pclntab variable from pcHeader
    #     }
    def __init__(self, pcHeader_addr) -> None:
        self.pcHeader_addr = pcHeader_addr
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


class ModuleData():
    '''
    Refer: https://golang.org/src/runtime/symtab.go

    // moduledata records information about the layout of the executable
    // image. It is written by the linker. Any changes here must be
    // matched changes to the code in cmd/internal/ld/symtab.go:symtab.
    // moduledata is stored in statically allocated non-pointer memory;
    // none of the pointers here are visible to the garbage collector.


// moduledata records information about the layout of the executable
// image. It is written by the linker. Any changes here must be
// matched changes to the code in cmd/internal/ld/symtab.go:symtab.
// moduledata is stored in statically allocated non-pointer memory;
// none of the pointers here are visible to the garbage collector.
    type moduledata struct {
	pcHeader     *pcHeader
	   []byte
	cutab        []uint32
	filetab      []byte
	pctab        []byte
	pclntable    []byte
	ftab         []functab
	findfunctab  uintptr
	minpc, maxpc uintptr

	text, etext           uintptr
	noptrdata, enoptrdata uintptr
	data, edata           uintptr
	bss, ebss             uintptr
	noptrbss, enoptrbss   uintptr
	end, gcdata, gcbss    uintptr
	types, etypes         uintptr

	textsectmap []textsect
	typelinks   []int32 // offsets from types
	itablinks   []*itab

	ptab []ptabEntry

	pluginpath string
	pkghashes  []modulehash

	modulename   string
	modulehashes []modulehash

	hasmain uint8 // 1 if module contains the main function, 0 otherwise

	gcdatamask, gcbssmask bitvector

	typemap map[typeOff]*_type // offset to *_rtype in previous module

	bad bool // module failed to load and should be ignored

	next *moduledata
}

    '''
    def __init__(self, start_addr):
        self.start_addr = start_addr

    def parse(self, is_test=False):
        if is_test:
            common._info("Test firstmoduledata addr: 0x%x" % self.start_addr)
        self.pcHeader = pcHeader(idc.get_qword(self.start_addr))
        self.funcnametab = idc.get_qword(self.start_addr + ADDR_SZ * 1)
        self.funcnametab_num = idc.get_qword(self.start_addr + ADDR_SZ * 1 + ADDR_SZ)
        self.funcnametab_cap = idc.get_qword(self.start_addr + ADDR_SZ * 1 + ADDR_SZ * 2)
        if is_test:
            return
        idc.set_name(self.start_addr, "module_data")

        next_base_addr = self.start_addr + ADDR_SZ * 1
        ida_bytes.create_qword(self.start_addr, 8, True)
        idc.set_cmt(self.start_addr, "pcHeader address", False)

        ida_bytes.create_qword(next_base_addr, 8 * 3, True)
        idc.set_cmt(next_base_addr, "funcnametab", False)
        idc.set_name(self.funcnametab, "funcnametab")

        self.cutab = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 1)
        # ida_bytes.create_qword(next_base_addr + ADDR_SZ * 3 * 1, 8 * 3, True)
        # idc.set_cmt(next_base_addr + ADDR_SZ * 3 * 1, "cutab", False)
        # idc.set_name(self.cutab, "cutab")

        self.filetab_addr = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 2)
        self.filetab_num = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 2 + ADDR_SZ)
        self.filetab_cap = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 2 + ADDR_SZ * 2)
        self.pctab = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 3)
        self.pclntable = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 4)
        self.functab = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 5)
        self.functab_num = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 5 + ADDR_SZ)
        self.functab_cap = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 5 + ADDR_SZ * 2)
        name_cmt_table = ["cutab", "filetab", "pctab", "pclntable", "ftab"]
        for i in range(1, 6):
            ida_bytes.create_qword(next_base_addr + ADDR_SZ * 3 * i, 8, True)
            ida_bytes.create_qword(next_base_addr + ADDR_SZ * 3 * i + ADDR_SZ, 8, True)
            ida_bytes.create_qword(next_base_addr + ADDR_SZ * 3 * i + ADDR_SZ * 2, 8, True)
            idc.set_cmt(next_base_addr + ADDR_SZ * 3 * i, name_cmt_table[i - 1], False)
            idc.set_name(idc.get_qword(next_base_addr + ADDR_SZ * 3 * i), name_cmt_table[i - 1])

        next_base_addr = next_base_addr + ADDR_SZ * 3 * 6
        name_cmt_table = ["findfunctab","minpc","maxpc","text","etext","noptrdata","enoptrdata","data","edata","bss","ebss","noptrbss","enoptrbss","end","gcdata","gcbss","types","etypes"]
        self.findfunctab = idc.get_qword(next_base_addr)
        self.min_pc = idc.get_qword(next_base_addr + ADDR_SZ * 1)
        self.max_pc = idc.get_qword(next_base_addr + ADDR_SZ * 2)
        self.text_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 3)
        self.etext_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 4)
        self.noptrdata_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 5)
        self.enoptrdata_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 6)
        self.data_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 7)
        self.edata_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 8)
        self.bss_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 9)
        self.ebss_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 10)
        self.noptrbss_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 11)
        self.enoptrbss_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 12)
        self.end_addr = idc.get_qword(next_base_addr + ADDR_SZ * 13)
        self.gcdata_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 14)
        self.gcbss_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 15)
        self.types_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 16)
        self.etypes_addr =  idc.get_qword(next_base_addr + ADDR_SZ * 17)
        for i in range(0, 18):
            ida_bytes.create_qword(next_base_addr + ADDR_SZ * i, 8, True)
            idc.set_cmt(next_base_addr + ADDR_SZ * i, name_cmt_table[i], False)
            idc.set_name(idc.get_qword(next_base_addr + ADDR_SZ * i), name_cmt_table[i])            

        next_base_addr = next_base_addr + ADDR_SZ * 18
        self.textsecmap_addr = idc.get_qword(next_base_addr)
        self.textsecmap_len = idc.get_qword(next_base_addr + ADDR_SZ * 1)
        self.textsecmap_cap = idc.get_qword(next_base_addr + ADDR_SZ * 2)
        self.typelink_addr = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 1)
        self.typelink_len = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 1 + ADDR_SZ)
        self.typelink_cap = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 1 + ADDR_SZ * 2)
        self.itablink_addr = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 2)
        self.itab_num = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 2 + ADDR_SZ)
        self.itab_cap = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 2 + ADDR_SZ * 2)
        self.ptab_addr = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 3)
        self.ptab_num = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 3 + ADDR_SZ)
        self.ptab_cap = idc.get_qword(next_base_addr + ADDR_SZ * 3 * 3 + ADDR_SZ * 2)

        name_cmt_table = ["textsectmap", "typelinks", "itablinks", "ptabEntry"]
        for i in range(4):
            for j in range(3):
                ida_bytes.create_qword(next_base_addr + ADDR_SZ * 3 * i + ADDR_SZ * j, 8, True)
            idc.set_cmt(next_base_addr + ADDR_SZ * 3 * i, name_cmt_table[i], False)
            idc.set_name(idc.get_qword(next_base_addr + ADDR_SZ * 3 * i), name_cmt_table[i])

        next_base_addr = next_base_addr + ADDR_SZ * 3 * 4
        self.pluginpath_addr = idc.get_qword(next_base_addr)
        ida_bytes.create_qword(next_base_addr, 8, True)
        ida_bytes.create_qword(next_base_addr + ADDR_SZ, 8, True)
        idc.set_cmt(next_base_addr, "plugin path", False)
        idc.set_name(self.pluginpath_addr, "pluginpath_name")
        self.pluginpath_len = idc.get_qword(next_base_addr + ADDR_SZ * 1)
        self.pluginpath = idc.get_bytes(self.pluginpath_addr, self.pluginpath_len)
        idc.create_strlit(self.pluginpath_addr, self.pluginpath_addr + self.pluginpath_len)

        next_base_addr = next_base_addr + ADDR_SZ * 2
        self.pkghashes_addr = idc.get_qword(next_base_addr)
        self.pkghashes_num = idc.get_qword(next_base_addr + ADDR_SZ * 1)
        self.pkghashes_cap = idc.get_qword(next_base_addr + ADDR_SZ * 2)
        for i in range(3):
            ida_bytes.create_qword(next_base_addr + ADDR_SZ * i, True)
        idc.set_name(self.pkghashes_addr, "pkghashes")
        idc.set_cmt(next_base_addr, "pkghashes", False)

        next_base_addr = next_base_addr + ADDR_SZ * 3
        self.modulename_addr = idc.get_qword(next_base_addr)
        ida_bytes.create_qword(next_base_addr, 8, True)
        ida_bytes.create_qword(next_base_addr + ADDR_SZ, 8, True)
        idc.set_cmt(next_base_addr, "modulename", False)
        idc.set_name(self.modulename_addr, "modulename")
        self.modulename_len = idc.get_qword(next_base_addr + ADDR_SZ * 1)
        self.modulename = idc.get_bytes(self.modulename_addr, self.modulename_len)
        idc.create_strlit(self.modulename_addr, self.modulename_addr + self.modulename_len)

        next_base_addr = next_base_addr + ADDR_SZ * 2
        self.modulehashes_addr = idc.get_qword(next_base_addr)
        self.modulehashes_num = idc.get_qword(next_base_addr + ADDR_SZ * 1)
        self.modulehashes_cap = idc.get_qword(next_base_addr + ADDR_SZ * 2)
        for i in range(3):
            ida_bytes.create_qword(next_base_addr + ADDR_SZ * i, True)
        idc.set_name(self.modulehashes_addr, "modulehashes")
        idc.set_cmt(next_base_addr, "modulehashes", False)

        next_base_addr = next_base_addr + ADDR_SZ * 3
        ida_bytes.create_byte(next_base_addr, 1, True)
        self.hasmain = ida_bytes.get_byte(next_base_addr)
        idc.set_cmt(next_base_addr, "hasmain", False)

        self.next_module_addr = idc.get_qword(next_base_addr + ADDR_SZ * 5 + 1)
        idc.set_cmt(next_base_addr + ADDR_SZ * 5 + 1, "next_module_addr\n This module data structed end here! ", False)
        self.parsed = True
        