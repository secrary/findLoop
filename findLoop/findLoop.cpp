#include "pch.h"

#include "dr_api.h"
#include "drmgr.h"

#include <string>
#include <unordered_map>


constexpr auto ITER_LIMIT = 200;

/* Application module */
static app_pc baseAddress;

/* Base address */

/* Blocks */
static std::unordered_map<DWORD_PTR, size_t> blocks;
static std::string target_name;

static void
event_exit(void);

static dr_emit_flags_t
event_app_instruction(void* drcontext, void* tag, instrlist_t* bb, instr_t* inst,
                      bool for_trace, bool translating, void* user_data);

static void
ProcessBlock(DWORD_PTR);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char* argv[])
{
	UNREFERENCED_PARAMETER(id);
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	dr_set_client_name("Find possible encryption/decryption, compression/decompression blocks",
	                   "https://github.com/secrary/");


	drmgr_init();

	target_name = dr_get_application_name();

	const auto mainModule = dr_get_main_module();
	if (mainModule != nullptr)
		baseAddress = mainModule->start;
	dr_free_module_data(mainModule);

	/* also give notification to stderr */
	if (dr_is_notify_on())
	{
		dr_enable_console_printing();
	}

	/* register events */
	dr_register_exit_event(event_exit);

	drmgr_register_bb_instrumentation_event(nullptr, event_app_instruction, nullptr);
}

static void
event_exit(void)
{
	std::string idaScript =
		R"(
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

	for (const auto block : blocks)
	{
		if (block.second > ITER_LIMIT) // more than 20 iteration
		{
			// block.first: address
			idaScript += std::to_string(block.first) + ", ";
		}
	}

	idaScript += "]\n";

	idaScript +=
		R"(
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

	auto idaScriptName = target_name + "_findLoop.py";
	auto fd = dr_open_file(idaScriptName.c_str(), DR_FILE_WRITE_OVERWRITE);
	dr_write_file(fd, idaScript.c_str(), idaScript.size()); // write IDA Pro script
	dr_close_file(fd);

	drmgr_exit();
}

static dr_emit_flags_t
event_app_instruction(void* drcontext, void* tag, instrlist_t* bb, instr_t* inst,
                      bool for_trace, bool translating, void* user_data)
{
	UNREFERENCED_PARAMETER(user_data);
	UNREFERENCED_PARAMETER(translating);
	UNREFERENCED_PARAMETER(for_trace);

	drmgr_disable_auto_predication(drcontext, bb);

	const auto mod = dr_lookup_module(dr_fragment_app_pc(tag));
	if (mod != nullptr)
	{
		const auto mainModule = (mod->start == baseAddress);
		dr_free_module_data(mod);
		if (!mainModule)
		{
			return DR_EMIT_DEFAULT;
		}
	}

	if (!drmgr_is_first_instr(drcontext, inst))
		return DR_EMIT_DEFAULT;

	const auto instrFirst = instrlist_first(bb);

	if (instr_is_return(instrFirst))
		return DR_EMIT_DEFAULT;

	// check if "application (non-meta)" instruction
	if (!instr_is_app(instrFirst))
		return DR_EMIT_DEFAULT;

	const auto instructionAddress = reinterpret_cast<DWORD_PTR>(instr_get_app_pc(instrFirst)) - DWORD_PTR(baseAddress);
	dr_insert_clean_call(drcontext, bb, instrlist_first_app(bb), static_cast<void *>(ProcessBlock),
	                     false /* save fpstate */, 1, OPND_CREATE_INTPTR(instructionAddress));


	return DR_EMIT_DEFAULT;
}

static void ProcessBlock(DWORD_PTR instructionAddress)
{
	if (blocks.find(instructionAddress) == blocks.end())
	{
		blocks[instructionAddress] = 1;
	}
	else
	{
		blocks[instructionAddress]++;
	}
}
