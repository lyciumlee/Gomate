#!/usr/bin/env python3.9
# -*- coding: UTF-8 -*-

"""
IDA plugin for Golang 1.16 executable eraser
"""

from go_parser import DEBUG
from pclntbl import Pclntbl

import ida_bytes
import sys
import common
import idaapi
import types_builder
DEBUG = False
if DEBUG:
    import wingdbstub
    wingdbstub.Ensure()
sys.setrecursionlimit(100000)
idaapi.require("moduledata")
idaapi.require("common")
idaapi.require("types_builder")
idaapi.require("pclntbl")
from moduledata import ModuleData
import moduledata
import types_builder

def main():
    firstmoddata_addr = moduledata.find_first_moduledata_addr()
    print("firts module data vaddr: ", hex(firstmoddata_addr))
    first_mod = ModuleData(firstmoddata_addr)
    first_mod.parse()
    first_pclntab = Pclntbl(first_mod.pcHeader.pcHeader_addr, first_mod)
    first_pclntab.parse()
    common._debug("begin erase function name")
    first_pclntab.eraser()
    type_parser = types_builder.TypesParser(first_mod)
    type_parser.build_all_types()
    type_parser.eraser()



if __name__ == '__main__':
    main()

