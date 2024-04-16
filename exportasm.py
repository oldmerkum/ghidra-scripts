#Export assembly instructions for functions of a binary
#@author oldmerkum
#@category assembly
#@keybinding
#@menupath Tools.Misc.Export asm functions
#@toolbar

from ghidra.program.model.block import BasicBlockModel
import time

asm_filename = askFile("asm filename", "filename")

with open(asm_filename.getPath(), "w") as asm_outfile:
  asm_outfile.write(currentProgram.getName() + "::ghidra assembly output\n")

  addr_fact = currentProgram.getAddressFactory()
  fxn_manager = currentProgram.getFunctionManager()
  code_manager = currentProgram.getCodeManager()

  code_block_model = BasicBlockModel(currentProgram)

  monitor.initialize(fxn_manager.getFunctionCount())

  current_count = 1

  for fxn in fxn_manager.getFunctions(True):
    monitor.setMessage("Working on function " + str(current_count) + " " + fxn.getName())

    asm_outfile.write(';' + fxn.getName() + "\n")

    for block in code_block_model.getCodeBlocksContaining(fxn.getBody(), monitor):
      asm_outfile.write('::block\n')
      for instr in code_manager.getInstructions(block, True):
        asm_outfile.write(instr.toString() + "\n")

    monitor.checkCanceled()
    monitor.incrementProgress(1)
    current_count = current_count + 1
