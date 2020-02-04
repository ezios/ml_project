# !/usr/bin/env python
# coding: utf-8
from os import listdir ,path

import lief
import hashlib
import numpy as np
import pickle
import time


#https://www.symantec.com/connect/blogs/cwindowssystem32-files-explained
#https://www.blackhat.com/docs/us-15/materials/us-15-Davis-Deep-Learning-On-Disassembly.pdf
with open("top_160_libs.pickle","rb") as f :                
    common_libraries = pickle.load(f)

# getattr(a,b) eq a.b vrai si la propriéts existe faux sinon
# retourne un tableau float ,prend argument pe.parse
def get_flags(exe):
    # quarkslabs propriétés des PE
    pe_properties = ["has_configuration", "has_debug", "has_exceptions",
                     "has_exports", "has_import", "has_nx",
                     "has_relocations", "has_resources",
                     "has_rich_header", "has_signature", "has_symbol",
                     "has_tls"]
    temp = []
    for has in pe_properties:
        if getattr(exe, has):
            temp.append(1.0)
        else:
            temp.append(0.0)
    return (np.array(temp))


# histogramme : combien de fois se repete une séquence de bytes
# divise par somme normalisation
"""def histogram(exe_raw):
    #global hbytes
    tab = np.array(list(exe_raw))
    histogram =[]
    for byte in hbytes:
        histogram.append(float(tab.count(byte)))
    _,histogram = np.unique(tab,return_counts=True)
    somme = sum(histogram)
    print(histogram)
    if somme > 0:
        return np.array(histogram) / somme
    return np.array(histogram)"""
def histogram(raw):
    histo = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256)
    histo = histo / histo.sum() # normalize
    print (len(histo))
    print(histo)
    time.sleep(10)
    return  histo

def get_metadata(exe , exe_raw):
    ent = float(exe.entrypoint)
    sz = float(len(exe_raw))
    return np.array([ent, sz])


# histogramme sur le nombre de fonctions appelées
def libcount(exe):
    current_pe_lib = {}
    number_of_functions = []
    global common_libraries

    for dll in exe.imports:
        current_pe_lib.update( { dll.name.lower() : float(len(dll.entries)) } )

    for lib in common_libraries:
        if lib in current_pe_lib:

            number_of_functions.append(current_pe_lib[lib])

        else:

            number_of_functions.append(0.0)
    somme = sum(number_of_functions)
    if somme > 0 : 
        return np.array(number_of_functions) / sum(number_of_functions)
    return np.array(number_of_functions)


def parse(file_path):
    try:
        pe_exe = lief.PE.parse(file_path)
        with open(file_path,"rb") as f:
            raw_pe_exe = f.read()
    except:
        return 0
    return (pe_exe,raw_pe_exe)


def get_hash(bin_file):
    hasher = hashlib.md5()
    hasher.update(bin_file)
    return hasher.hexdigest()
hbytes = np.array([chr(i) for i  in range(256)])
directory = "/home/abbe/Bureau/ml_project/VShare"
print(directory)
files = listdir(directory)
features = []
hashes = []
print(str(len(files))+" found")
print("start processing features")
count = 0

for file in files:
    f_exe = path.join(directory,file)
    pe = parse(f_exe)
    if pe:
        count+=1
        parsed = pe[0]
        raw =    pe[1]

        i_d = get_hash(raw)
        flags = get_flags(parsed)
        hist = histogram(raw)
        n_libs = libcount(parsed)

        pe_features = np.concatenate([flags,hist,n_libs])
    features.append(pe_features)    
    hashes.append(i_d)
    print(count, end="\r")

print("")
hashes   = np.array(hashes)
features = np.array(features)

with open("features/m_hashes","wb") as h,open("features/m_features","wb") as f:
    np.ndarray.dump(hashes,h)
    np.ndarray.dump(features,f)
print("[+] Done ")
