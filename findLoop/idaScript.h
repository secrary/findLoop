#pragma once
#include <string>

std::string first = R"(
# -------------------------------------------------------------------------------
#
# Copyright (c) 2019
# Lasha Khasaia @_qaz_qaz
#
# -------------------------------------------------------------------------------

from __future__ import print_function
import ida_bytes
import ida_funcs
import idaapi
import idc

addresses = [
)";

std::string second = R"(
imageBase = idaapi.get_imagebase()

# return (start_ea, size)
def getFuncRanges():
    start = 0
    next_func =  ida_funcs.get_next_func(start)
    function_start_end = {}
    while next_func:
        function_start_end[next_func.start_ea] = next_func.end_ea
        next_func = ida_funcs.get_next_func(next_func.start_ea)
    return function_start_end

# we looking for loops inside a function
# blacklist function starts
blacklisted_functions = [] # start, end
functions_table = getFuncRanges()
for rva in addresses:
    address = rva + imageBase
    if functions_table.has_key(address):
        fnc = ida_funcs.get_func(address)
        blacklisted_functions.append(fnc)

loop_addresses = []
for rva in addresses:
    address = rva + imageBase
    flags = ida_bytes.get_flags(address)
    if not ida_bytes.is_code(flags):
        print("[findLoop] {}: not an instruction".format(hex(address)))
        continue
    
    valid = True
    for fnc in blacklisted_functions:
        if ida_funcs.func_contains(fnc, address):
            valid = False
            break
    if valid:
        loop_addresses.append(address)
    
    
loop_addresses = set(loop_addresses)
print("[findLoop] Possible encryption/decryption or compression/decompression code:")
for address in loop_addresses:
    idc.set_color(address, CIC_ITEM, 0x36AD80) # set color: green
    idc.add_bpt(address)
    print("0x{:x}".format(address))

print()
)";
