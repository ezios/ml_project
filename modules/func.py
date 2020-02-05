#some functions
from os import path,listdir

def get_file_list(directory):
	files = listdir(directory)
	all_files =[]
	for file in files:
		all_files.append(path.join(directory,file))
	print(str(len(files))+" found")
	return all_files