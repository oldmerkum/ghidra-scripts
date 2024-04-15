#Export assembly instructions for functions of a binary
#@author oldmerkum
#@category assembly
#@keybinding 
#@menupath Tools.Misc.Export asm functions
#@toolbar 

import time

asm_filename = askFile("asm filename", "filename")

with open(asm_filename.getPath(), "w") as asm_outfile:
  asm_outfile.write(currentProgram.getName() + "::ghidra assembly output\n")

  addr_fact = currentProgram.getAddressFactory()
  fxn_manager = currentProgram.getFunctionManager()
  code_manager = currentProgram.getCodeManager()

  monitor.initialize(fxn_manager.getFunctionCount())

  current_count = 1

  for fxn in fxn_manager.getFunctions(True):
    monitor.setMessage("Working on function " + str(current_count) + " " + fxn.getName())

    asm_outfile.write(';' + fxn.getName() + "\n")
    for instr in code_manager.getInstructions(fxn.getBody(), True):
      asm_outfile.write(instr.toString() + "\n")

    monitor.checkCanceled()
    monitor.incrementProgress(1)
    current_count = current_count + 1
