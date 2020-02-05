#get_features return a numpy array

import lief_features
import disass
import numpy as np
import sys



def features(file):
	a = lief_features.get_l_features(file)
	b = disass.get_features(file)
	return np.concatenate([a,b])
