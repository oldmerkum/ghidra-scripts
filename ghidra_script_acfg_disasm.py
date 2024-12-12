import base64
import json
import csv
import ntpath
import os
import sys
import time
import itertools

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.lang import OperandType

from collections import namedtuple
import codecs

COLUMNS = [
    'firmware',
    'fva',
    'func_name',
    ]

BasicBlock = namedtuple('BasicBlock', ['va', 'size', 'succs'])


# setup utils
Utils = namedtuple(
  'Utils',
  ['addr_fact', 'fxn_manager', 'code_manager', 'code_block_model']
)

utils = Utils(
  currentProgram.getAddressFactory(),
  currentProgram.getFunctionManager(),
  currentProgram.getCodeManager(),
  BasicBlockModel(currentProgram)
)

def convert_procname_to_str(procname, bitness):
    """Convert the arch and bitness to a std. format."""
    if procname == 'mipsb':
        return "mips-{}".format(bitness)
    if procname == "arm":
        return "arm-{}".format(bitness)
    if "pc" in procname:
        return "x86-{}".format(bitness)
    raise RuntimeError(
        "[!] Arch not supported ({}, {})".format(
            procname, bitness))

def get_prefix(procname):
    prefix = "UNK_"

    # WARNING: mipsl mode not supported here
    if procname == 'mipsb':
        prefix = "M_"
    if procname == "arm":
        prefix = "A_"
    if "pc" in procname:
        prefix = "X_"
    return prefix

def get_bytes_and_addr(inst):
    hex_str = ''
    for byte in inst.getBytes():
        if byte > 0:
            hex_str += '{:02x}'.format(byte)
        else:
            hex_str += '{:02x}'.format(byte & 0xff)
    data = codecs.decode(hex_str, 'hex')
    addr_str = inst.getAddress().toString()
    addr = int(addr_str, 16)
    return data, addr

def ghidra_disassembly(bb, prefix):
    """Return the BB (normalized) disassembly, with mnemonics and BB heads."""
    try:
        bb_heads, bb_mnems, bb_disasm, bb_norm = list(), list(), list(), list()

        # Iterate over each instruction in the BB
        for inst in utils.code_manager.getInstructions(bb, True):
            data, addr = get_bytes_and_addr(inst)
            mnemonic = inst.getMnemonicString()
            # Get the address
            bb_heads.append(addr)
            # Get the mnemonic
            bb_mnems.append(mnemonic)
            # Get the disasm
            bb_disasm.append(inst.toString())

            # Compute the normalized code. Ignore the prefix.
            # cinst = prefix + i_inst.mnemonic
            cinst = mnemonic

            # Iterate over the operands
            for op_index in range(0, inst.getNumOperands()):
                op = inst.getOpObjects(op_index)
                op_type = inst.getOperandType(op_index)
                op_type_str = OperandType().toString(inst.getOperandType(op_index))
                op_str = inst.getDefaultOperandRepresentation(op_index)

                cinst += '_' + op_str
            bb_norm.append(cinst)

        return bb_heads, bb_mnems, bb_disasm, bb_norm

    except Exception as e:
        print("[!] Ghidra exception", e)
        return list(), list(), list(), list()

def get_bb_disasm(bb, prefix):
    """Return the (nomalized) disassembly for a BasicBlock."""
    bb_data = ''
    for inst in utils.code_manager.getInstructions(bb, True):
        data, _ = get_bytes_and_addr(inst)
        bb_data += data
    b64_bytes = base64.b64encode(bb_data)
    bb_heads, bb_mnems, bb_disasm, bb_norm = \
        ghidra_disassembly(bb, prefix)
    return b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm

def process_function(fxn, prefix):
    start_time = time.time()
    nodes_set, edges_set = set(), set()
    bbs_dict = dict()
    for bb in utils.code_block_model.getCodeBlocksContaining(fxn.getBody(), monitor):
        # CFG
        start_address = int(bb.getFirstStartAddress().toString(), 16)
        size = bb.getNumAddresses()
        nodes_set.add(start_address)
        dests = bb.getDestinations(monitor)
        while dests.hasNext():
            dest = dests.next()
            dest_address = int(dest.getDestinationAddress().toString(), 16)
            edges_set.add((start_address, dest_address))
        # BB-level features
        if size:
            b64_bytes, bb_heads, bb_mnems, bb_disasm, bb_norm = \
                get_bb_disasm(bb, prefix)
            bbs_dict[start_address] = {
                'bb_len': size,
                'b64_bytes': b64_bytes,
                'bb_heads': bb_heads,
                'bb_mnems': bb_mnems,
                'bb_disasm': bb_disasm,
                'bb_norm': bb_norm
            }
        else:
            bbs_dict[start_address] = {
                'bb_len': size,
                'b64_bytes': "",
                'bb_heads': list(),
                'bb_mnems': list(),
                'bb_disasm': list(),
                'bb_norm': list()
            }
    elapsed_time = time.time() - start_time
    func_dict = {
        'name': ('"' + fxn.getName(True) + '"'),
        'nodes': list(nodes_set),
        'edges': list(edges_set),
        'elapsed_time': elapsed_time,
        'basic_blocks': bbs_dict
    }
    return func_dict

def run_acfg_disasm(firmware_name, fva_list, output_dir):
    """Disassemble each function. Extract the CFG. Save output to JSON."""
    print("[D] Processing: %s" % firmware_name)

    csv_name = ntpath.basename(firmware_name) + "_function_names.csv"
    print(output_dir)
    print(csv_name)
    csv_out = open(os.path.join(output_dir, csv_name), 'w')
    csv_out.write(",".join(COLUMNS) + "\n")


    output_dict = dict()
    output_dict[firmware_name] = dict()

    procname = currentProgram.metadata['Processor'].lower()
    bitness = int(currentProgram.metadata['Address Size'])
    prefix = get_prefix(procname)
    output_dict[firmware_name]['arch'] = "{}-{}".format(procname, bitness)

    # Iterate over each function
    if len(fva_list) > 0:
        for fva in fva_list:
            fxn_addr = utils.addr_fact.getAddress(fva)
            fxn = utils.fxn_manager.getFunctionAt(fxn_addr)
            output_dict[firmware_name][fva] = process_function(fxn, prefix)
            csv_out.write(','.join(
                [firmware_name, fva, output_dict[firmware_name][fva]['name']])
                + '\n')
    else:
        for fxn in utils.fxn_manager.getFunctions(True):
            fva = int(fxn.getEntryPoint().toString(), 16)
            output_dict[firmware_name][fva] = process_function(fxn, prefix)
            csv_out.write(','.join(
                [firmware_name, str(fva), output_dict[firmware_name][fva]['name']])
                + '\n')
    csv_out.close()

    out_name = ntpath.basename(firmware_name)+"_acfg_disasm.json"
    with open(os.path.join(output_dir, out_name), "w") as f_out:
        json.dump(output_dict, f_out)

if __name__ == '__main__':
    args = getScriptArgs()
    firmware_name = args[0]
    output_dir = args[1]
    if len(sys.argv) > 2:
        selected_functions_csv = args[2]
        with open(selected_functions_csv) as f_in:
            csv_reader = csv.reader(f_in)
            fva_list = list(itertools.chain.from_iterable(list(csv_reader)))[1:]
        print("[D] Found %d addresses" % len(fva_list))
    else:
        fva_list = []
        print("[D] No address list, gathering all functions...")

    run_acfg_disasm(firmware_name, fva_list, output_dir)
