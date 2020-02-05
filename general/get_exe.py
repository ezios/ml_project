import os
import shutil
import sys
import lief
#get benign file from Windows partition (scanned with AV before)


def copy_file(src, dest):
    # copy file from source to destination
  try:
   shutil.copy(src, dest)
    # eg. source and destination are the same file
  except shutil.Error as e:
   print('Error: {0}'.format(e))
  # eg. source or destination doesn't exist
  except IOError as e:
   print('Error: {0}'.format(e.strerror))
#path will be windows partition 
path = sys.argv[1]

# retrieve all windows PE
for root,dirs,file in os.walk(path):
	for file_name in file:
		file_path = os.path.join(root, file_name)
		try:
			lief.PE.parse(os.path.join(root,file_name))
			copy_file(file_path,"ml_project/benign/")
		except :
			pass
