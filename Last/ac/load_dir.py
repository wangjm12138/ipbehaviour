# -*- coding: utf-8 -*-
#import ahocorasick
import pickle
fn = 'dir_traver.pkl'
with open(fn,'br') as f:
	actree_test = pickle.load(f)

test_str = ['xvxds..\\../../..\\as','xxxx']
for item in test_str:
	print(item)
	c = [i for i in actree_test.iter(item)]
	#print (result,type(result),len(result))
	print (c)

