#compute features
#coding:utf-8

import lief
import hashlib
import numpy as np
import pickle




with open("data/top_160_libs.pickle","rb") as f :                
    common_libraries = pickle.load(f)

def get_flags(exe):
    # quarkslabs propriétés des PE , renvoie 1 si le PE possède 
    #la propriété et 0 sinon 
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
    return (np.array(temp,dtype = np.float64))


def histogram(raw):
 	#compte la fréquence des bytes sur le fichier
    histo = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256)
    histo = histo / histo.sum() # normalize
    return  np.array(histo , dtype=np.float64)

# histogramme sur le nombre de fonctions appelées dans une dll
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
    return np.array(number_of_functions,dtype=np.float64)



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

def get_l_features(file_path):

	with open(file_path,"rb") as f:
		f_data = f.read()
	try:
		pe = parse(file_path)
	except:
		print( "error while parsing, not PE")
		sys.exit()
	parsed = pe[0]
	raw =    pe[1]
	i_d = get_hash(raw)
	flags = get_flags(parsed)
	hist = histogram(raw)
	n_libs = libcount(parsed)
	pe_features = np.concatenate([flags,hist,n_libs])
	return pe_features
