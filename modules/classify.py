#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from keras.models import Sequential
from keras.layers import Dense
from keras.models import model_from_json
import os
import numpy 
import pandas
import matplotlib.pyplot as plt


# In[3]:


filepath = "C:/Downloads/dataset2.csv"
dataset = pandas.read_csv(filepath)


# In[4]:


array = dataset.values


# In[6]:


X = array[:,0:437]
Y = array[:,437]


# In[7]:


model = Sequential()
model.add(Dense(450, input_dim=437, activation='relu'))
model.add(Dense(300, activation='relu'))
model.add(Dense(200, activation='relu'))
model.add(Dense(120, activation='relu'))
model.add(Dense(1, activation='sigmoid'))


# In[8]:


model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])


# In[9]:


model.fit(X, Y, epochs=150, batch_size=12)


# In[19]:


_, accuracy = model.evaluate(X, Y)
print('Accuracy: %.2f' % (accuracy*100))
Ypredict = model.predict_classes(X)
from sklearn.metrics import confusion_matrix
conf = confusion_matrix(Y,Ypredict)
print(conf)


# In[20]:


# serialize model to JSON
model_json = model.to_json()
with open("C:/Downloads/model.json", "w") as json_file:
    json_file.write(model_json)
    
# serialize weights to HDF5
model.save_weights("C:/Downloads/model.h5")
print("Saved model to disk")
 
 


# In[23]:


import pickle
with open("C:/downloads/tweakpng.dump","rb") as f:
    Xnew = numpy.array([pickle.load(f)])
print(Xnew.shape)
# make a prediction
ynew = model.predict_classes(Xnew)
#show the inputs and predicted outputs
print("X=%s, Predicted=%s" % (Xnew[0], ynew[0]))


# In[ ]:




