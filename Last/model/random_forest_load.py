import os
import socket
import struct
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

filename = "classfier.txt"
feature_columns=['Sum_sec_flow','Feq_sec_flow','Sum_xss','Feq_xss','Sum_dir','Feq_dir','Sum_404_error',\
						        'Feq_404_error','H_status','src_ip','dest_ip','Malics_urls','lable']

feature_content = pd.read_table(filename,header=None,sep='\t',index_col=None,names=feature_columns)
print(feature_content)
X_train, X_test, y_train, y_test = train_test_split(feature_content[['Sum_sec_flow','Feq_sec_flow','Feq_xss','Feq_dir','Feq_404_error','H_status']].values,\
		feature_content[['lable']].values , test_size=0.4, random_state=42)

fn = 'random_forest.pkl'

with open(fn,'rb') as f:
	model = pickle.load(f)

preds = model.predict(X_train)
for i,item in enumerate(preds):
	print(item,y_train[i]),

