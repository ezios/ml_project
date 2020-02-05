import lief
from collections import Counter
from os import listdir,path

def libcount(exe):
    current_pe_lib = []
    for dll in exe.imports:
        current_pe_lib.append(dll.name.lower())
    print(len(current_pe_lib),end='\r')
    return current_pe_lib


directory = "ml_project/dataset"
files = listdir(directory)

count = 0
common_libs=[]

for file in files:
    f_exe = path.join(directory,file)
    try:
        pe_exe = lief.PE.parse(f_exe)
    except:
    	pass
    t = libcount(pe_exe)	
    for i in t :
    	common_libs.append(i)


count = Counter(common_libs)

with open("benign_libstats","w") as f:
	for k in count.keys():
		f.write(str(k)+"\n")

print("[+] done")
