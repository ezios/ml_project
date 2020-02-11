#coding:utf-8
import numpy as np
import pickle
import pandas
import matplotlib.pyplot as plt
from pandas.plotting import scatter_matrix
debug=0

# load pickle dumped malware and benign features with their hashes , libs are the common libs in our dataset
with open("../data/b_features","rb") as bf , \
     open("../data/b_hashes","rb") as bh,\
     open("../data/m_features","rb") as mf ,\
     open("../data/m_hashes","rb") as mh, \
     open("../data/disass_mm_features","rb") as dmf ,\
     open("../data/disass_mm_hashes","rb") as dmh ,\
     open("../data/disass_b_features","rb") as dbf,\
     open("../data/disass_b_hashes","rb") as dbh ,\
     open("../data/top_libs","r") as f:
        benfeatures = pickle.load(bf)
        benhashes   = pickle.load(bh)
        malfeatures = pickle.load(mf)
        malhashes   = pickle.load(mh)
        dmalf       = pickle.load(dmf,encoding='latin1')
        dmalh       = pickle.load(dmh)
        dbenf       = pickle.load(dbf,encoding='latin1')
        dbenh       = pickle.load(dbh)
        libs        = f.read()
libs= libs.split("\n")
libs.remove("")

if debug :
    
    print(benfeatures.shape)
    print(benhashes.shape)
    print(malfeatures.shape)
    print(malhashes.shape)
    print("disassembled")
    print(dmalf.shape)
    print(dmalh.shape)
    print(dbenf.shape)
    print(dbenh.shape)
    print(dbenf[4])

lfeatures ={}
dfeatures ={}
lmfeatures={}
dmfeatures={}

#create dictionnary of {hashes:features} eg: {"ab12hd799977777":[0.,0.,2.,4.34443,]}
for i in range(len(benfeatures)):
    lfeatures.update({benhashes[i]:benfeatures[i]})
for i in range(len(dbenf)):
    dfeatures.update({dbenh[i]:dbenf[i]})
    
for i in range(len(malfeatures)):
    lmfeatures.update({malhashes[i]:malfeatures[i]})
for i in range(len(dmalf)):
    dmfeatures.update({dmalh[i]:dmalf[i]})
    
if debug:
    print(len(lmfeatures))
    print(len(dmfeatures))
    print(lmfeatures[malhashes[340]])
    print(dmfeatures[dmalh[230]])

#concatening features from lief and disassembled ones
benign   = []
malign   = []
rownames = []
y        = []
#benign  1
for hash in dfeatures.keys():
    benign.append(np.concatenate((lfeatures[hash.decode()],dfeatures[hash]),axis=0))
    rownames.append(hash.decode())
    y.append(np.float64(1))

#malign 0
for hash in dmfeatures.keys():
    malign.append(np.concatenate((lmfeatures[hash.decode()],dmfeatures[hash]),axis=0))
    rownames.append(hash.decode())
    y.append(np.float64(0))


benign = np.array(benign,dtype = np.float64)M
malign = np.array(malign,dtype=np.float64)
y      = np.array([y],dtype = np.float64)
t_array = np.concatenate((benign,malign),axis=0)
t_array = np.concatenate((t_array,y.T),axis =1)

h_features= ["has_configuration", "has_debug", "has_exceptions","has_exports", "has_import", "has_nx",
          "has_relocations", "has_resources","has_rich_header", "has_signature", "has_symbol","has_tls"]
hbytes    = [hex(i) for i  in range(256)]
symb = ["-","+", "*", "[", "?","@","db","dw","dd"]
colnames = h_features+hbytes+libs+symb+["classe"]

dataset = pandas.DataFrame(t_array, index=rownames, columns=colnames)

dataset.to_csv(r"../data/dataset2.csv",index=False)
