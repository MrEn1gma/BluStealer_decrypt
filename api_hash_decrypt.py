import lief
import idaapi

def getHash(start_addr, end_addr):
    out = []
    while(start_addr < end_addr):
        tmp = idc.GetDisasm(start_addr)
        if(str(tmp).startswith("push") and 
           str(tmp).endswith("h") and 
           len(tmp[8:-1]) >= 8 and 
           (str(tmp[8:-1]).startswith("7") or str(tmp[8:-1]).startswith("0"))):
            out.append(get_operand_value(start_addr, 0))
        start_addr = idc.next_head(start_addr)
    return out

def CalculateHash(f_name):
    name = [ord(i) for i in f_name]
    spec_num = 8998
    for i in range(len(name)):
        spec_num += name[i] + (((spec_num >> 1) & 0xffffffff) | ((spec_num << 7) & 0xffffffff))
        final_hash = spec_num & 0xffffffff
        
    return final_hash

def malware101_api_from_dll(full_path_dll_name):
    out = []
    for idxDll in full_path_dll_name:
        dll = lief.parse(idxDll)
        for i in range(len(dll.exported_functions)):
            function_name = dll.exported_functions[i].name
            out.append((CalculateHash(function_name), function_name))
        
    return out

def malware101_find_api_hash(hash_config, api_hashs):
    for j in range(len(api_hashs)):
        for k in range(len(hash_config)):
            if(hash_config[k][0] == api_hashs[j]):
                print("[+] " + hex(hash_config[k][0]) + " | " + hash_config[k][1])
                
    print("DONE.")

hashes = getHash(0x5e090D, 0x5e0b54)                # start address of api hash
dll_paths = ["C:\Windows\System32\kernel32.dll", 
             "C:\Windows\System32\Shell32.dll", 
             "C:\Windows\System32\Shlwapi.dll", 
             "C:\Windows\System32\Advapi32.dll"]
print("Bruteforcing to find API by hash...")
malware101_find_api_hash(malware101_api_from_dll(dll_paths), hashes)