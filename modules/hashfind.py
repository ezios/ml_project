from func import get_file_list
import hashlib

def get_hash(bin_file):
    hasher = hashlib.md5()
    hasher.update(bin_file)
    return hasher.hexdigest()

def findhash(directory , list_of_hash):
	files = get_file_list(directory)
	result =[]
	for file in files : 
		with open(file,"rb") as f:
			if get_hash(f.read()) in list_of_hash:
				result.append(file)
	return result


if __name__ == '__main__':
	vraipostif = ["3a9f737dbb4a7bc6aa149693faf540f0",\
				  "f752052b9412ee0c1048dbf39a794e17",\
				  "e2312f199976d03a7cf41e453c5af246",\
				  "e70ac976a621fec17460f1f234662ef8",\
				  "03956494403ab2cdae8e892a7b293ff8",\
				  "2a4627ddff6f94893eb054362fed7cb2"]
	res = findhash("/home/abbe/Bureau/ml_project/benign/",vraipostif)
	for i in res: print(i)
