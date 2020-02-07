#https://www.capstone-engine.org/lang_python.html
#https://books.google.fr/books?id=3fxvDQAAQBAJ&pg=PA94&lpg=PA94&dq=use+pydbg+to+disassemble&source=bl&ots=-isTVTv-0w&sig=ACfU3U2-3yH5s6Zl5m4yJqgKbSVPIdIDtw&hl=\
#fr&sa=X&ved=2ahUKEwihyo7_5bjnAhUO_BQKHXZmCRcQ6AEwA3oECAoQAQ#v=onepage&q=use%20pydbg%20to%20disassemble&f=false


from capstone import *
from func import *

import pefile
import numpy as np

symb = ["-","+", "*", "[", "?","@","db","dw","dd"]

def disassemble(file):
		ops=[]
		pe = pefile.PE(file)
		entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		data = pe.get_memory_mapped_image()[entryPoint:]
		if pe.FILE_HEADER.Machine == 0x14c:
			cs = Cs(CS_ARCH_X86, CS_MODE_32)
		else : 
			cs = Cs(CS_ARCH_X86,CS_MODE_64)
		for i in cs.disasm(data, 0x1000):
			ops.append(i.mnemonic + " "+ i.op_str)

		return np.array(ops)

def sym_freq(disassembled):
	global symb
	frequency = {symb[i]:0 for i in range(len(symb))}
	for line in disassembled:
		for sy in symb:
			if sy in line:
				frequency[sy]+=1
	t = frequency.values()
	if sum(t)==0:
		return np.array([0 for i in range(9)],dtype=float) 
	return np.array(list(t), dtype = np.float64)/sum(t)

def get_features(file):
	return sym_freq ( disassemble(file) )
