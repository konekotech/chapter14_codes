#TODO write a description for this script
#@author konekotech
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime PyGhidra


#TODO Add User Code Here
import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.symbol import RefType

def get_called_functions_excluding_fun(func):
    """
    指定関数内で呼ばれている関数のうち、名前が"FUN_"で始まらない関数のリストを返す
    """
    called_funcs = set()
    listing = currentProgram.getListing()
    addr = func.getEntryPoint()
    end = func.getBody().getMaxAddress()

    while addr <= end:
        instr = listing.getInstructionAt(addr)
        if instr is not None:
            for ref in instr.getReferencesFrom():
                if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL or ref.getReferenceType().isCall():
                    called_func = getFunctionAt(ref.getToAddress())
                    if called_func and not called_func.getName().startswith("FUN_"):
                        called_funcs.add(called_func)
            addr = instr.getMaxAddress().next()
        else:
            addr = addr.next()

    return called_funcs


# main関数取得
main_func = getFunction("main")
if main_func is None:
    print("cannot find main function")
else:
    listing = currentProgram.getListing()
    addr = main_func.getEntryPoint()
    end = main_func.getBody().getMaxAddress()

    # main関数内で呼ばれているFUN_関数を集める
    fun_funcs = set()
    while addr <= end:
        instr = listing.getInstructionAt(addr)
        if instr is not None:
            for ref in instr.getReferencesFrom():
                if ref.getReferenceType() == RefType.UNCONDITIONAL_CALL or ref.getReferenceType().isCall():
                    called_func = getFunctionAt(ref.getToAddress())
                    if called_func and called_func.getName().startswith("FUN_"):
                        fun_funcs.add(called_func)
            addr = instr.getMaxAddress().next()
        else:
            addr = addr.next()

    # FUN_関数の中で呼ばれている、FUN_以外の関数を集める
    fun_called_nonfun_funcs = dict()
    print("main function: {}".format(main_func.getName()))
    main_called = get_called_functions_excluding_fun(main_func)
    for c in main_called:
        print("main calls: {} at {}".format(c.getName(), c.getEntryPoint()))
        if fun_called_nonfun_funcs.get(c) is None:
            fun_called_nonfun_funcs[c] = 1
        else:
            fun_called_nonfun_funcs[c] += 1
    for f in fun_funcs:
        print("checking function: {}".format(f.getName()))
        called = get_called_functions_excluding_fun(f)
        for c in called:
            print(" - {} at {}".format(c.getName(), c.getEntryPoint()))
            if fun_called_nonfun_funcs.get(c) is None:
                fun_called_nonfun_funcs[c] = 1
            else:
                fun_called_nonfun_funcs[c] += 1

    print("histgram of called functions:")
    for func, count in sorted(fun_called_nonfun_funcs.items(), key=lambda x: x[1], reverse=True):
        print("{}: {}".format(func.getName(), count))
