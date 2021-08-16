#!/usr/bin/env python3.9
# -*- coding: UTF-8 -*-

"""
IDA plugin for Golang 1.16 executable eraser
"""

from pclntbl import Pclntbl
from moduledata import ModuleData
import ida_bytes
import wingdbstub
import sys
import common
import idaapi

wingdbstub.Ensure()
sys.setrecursionlimit(10000)
idaapi.require("moduledata")
idaapi.require("common")
idaapi.require("pclntbl")

def main():
    firstmoddata_addr = moduledata.find_first_moduledata_addr()
    print("firts module data vaddr: ", hex(firstmoddata_addr))
    first_mod = ModuleData(firstmoddata_addr)
    first_mod.parse()
    first_pclntab = Pclntbl(first_mod.pcHeader.pcHeader_addr, first_mod)
    first_pclntab.parse()
    common._debug("begin erase function name")
    first_pclntab.eraser()


if __name__ == '__main__':
    main()

