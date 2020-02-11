
import lief_features
import disass
import os
import sys
import warnings
if not sys.warnoptions:
    warnings.simplefilter("ignore")
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import numpy as np

from keras.models import model_from_json



def features(file):
	a = lief_features.get_l_features(file)
	b = disass.get_features(file)
	return np.concatenate([a,b])

def get_nature(file_features):
	return loaded_model.predict_classes(np.array([file_features]))[0][0]







if __name__ == '__main__':

	try:
		sample = sys.argv[1]
	except Exception as e:
		print("usage : detect.py path_of/file/to/scan")
		raise e
		sys.exit()
	if not os.path.isfile(sample):
		print ("File not exist")
		sys.exit()

	model_path = "../data/model.json"
	h5 = "../data/model.h5"

	with open(model_path, 'r') as f:
		loaded_model_json = f.read()

	loaded_model = model_from_json(loaded_model_json)
	loaded_model.load_weights(h5)

	f=features(sample)
	prediction = get_nature(f)

	if prediction :
		print("file %s is safe" %sample)
	else:
		print("file %s is Malicious"%sample)
