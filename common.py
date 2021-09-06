#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import idc, idaapi, idautils
import string

DEBUG = True
ADDR_SZ = 8 # Default: 32-bit
GOVER = ""

if idaapi.get_inf_structure().is_64bit():
    ADDR_SZ = 8

def _info(info_str):
    print(info_str)

def _error(err_str):
    print('[ERROR] - %s' % err_str)

def _debug(dbg_str):
    global DEBUG
    if DEBUG:
        print('[DEBUG] - %s' % dbg_str)

def get_seg(seg_names):
    seg = None
    for seg_name in seg_names:
        seg = idaapi.get_segm_by_name(seg_name)
        if seg:
            return seg

    return seg

def get_seg_by_symname(sym_names):
    for sym_name in sym_names:
        for ea, name in idautils.Names():
            if name == sym_name:
                return idaapi.getseg(ea)

    return None

def get_text_seg():
    # .text found in PE & ELF binaries, __text found in macho binaries
    return get_seg(['.text', '__text'])

def find_func_by_name(func_name):
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.SegEnd(segea)):
            if func_name == idaapi.get_func_name(funcea):
                return idaapi.get_func(funcea)
    return None

def get_goroot():
    pass

def find_ret_cb(flow_chart):
    pass


STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
def clean_function_name(name_str):
    '''
    Clean generic 'bad' characters
    '''
    name_str = filter(lambda x: x in string.printable, name_str)

    for c in STRIP_CHARS:
        name_str = name_str.replace(c, '')

    for c in REPLACE_CHARS:
        name_str = name_str.replace(c, '_')

    return name_str

def get_goversion():
   pass