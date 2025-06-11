# Find Libc Functions by Head Bytes
# @category Libc Functions
# @runtime PyGhidra
# @author konekotech


# Ghidra Requirements
import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import hashlib
from ghidra.util.task import TaskMonitor

def get_function_head_bytes(func, program, length=16):
    if not func or not program:
        return None
    mem = program.getMemory()
    start = func.getEntryPoint()
    try:
        bytes_data = mem.getBytes(start, length)
        print(f"Function {func.getName()} @ {start} head bytes: {bytes_data.hex()}")
        return bytes_data
    except Exception:
        return None

def get_function_head_map(program, length=16):
    func_map = {}
    fm = program.getFunctionManager()
    funcs = fm.getFunctions(True)
    for func in funcs:
        if func.isThunk():
            continue
        bytes_data = get_function_head_bytes(func, program, length)
        if bytes_data:
            md5 = hashlib.md5(bytes_data).hexdigest()
            func_map[md5] = func.getName()
    return func_map

def compare_with_libc_head(libc_program, length=16):
    print(f"[*] Comparing current binary with libc using first {length} bytes...")
    current_map = get_function_head_map(currentProgram, length)
    libc_map = get_function_head_map(libc_program, length)
    matches = 0
    for md5, current_func_name in current_map.items():
        print(f"Checking function: {current_func_name} with MD5: {md5}")
        if md5 in libc_map:
            libc_func_name = libc_map[md5]
            print(f"Match found:\n - Binary Function: {current_func_name}\n - Libc Function:   {libc_func_name}\n")
            matches += 1

    print(f"[*] Total matches found: {matches}")

def find_libc_program_by_name(libc_name):
    """
    プロジェクトのフォルダを再帰的に検索してlibcを探す
    """
    project_data = state.getProject().getProjectData()
    root_folder = project_data.getRootFolder()

    def recursive_search(folder):
        for child in folder.getFiles():
            if libc_name in child.getName():
                print(f"[*] Found libc binary: {child.getName()}")
                # Programを開く（読み取り専用、非更新、モニター）
                program = child.getDomainObject(currentProgram, False, False, TaskMonitor.DUMMY)
                return program
        for subfolder in folder.getFolders():
            result = recursive_search(subfolder)
            if result:
                return result
        return None

    return recursive_search(root_folder)

# ===== 設定 =====
LIBC_NAME = "libc.so.5.3.12"

libc_program = find_libc_program_by_name(LIBC_NAME)
if libc_program:
    compare_with_libc_head(libc_program, length=16)
else:
    print(f"[!] Could not find or open libc binary with name: {LIBC_NAME}")
