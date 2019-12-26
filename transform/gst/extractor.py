import os
import re
import sys
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
#from parameters import parameters
import urllib
import base64
import math
from .utils import prepare_data_train,prepare_data_test
from .dataProcess import dataProcess
class extractor:
	
	def __init__(self,parameters):
		self.parameters = parameters

	def generate_feature_api(self,url_param_list=None):
		'''   generate feature for train, validation  or test
		'''
		if url_param_list is None:
			raise RuntimeError('The test data path is not known')
		else:
			X,original_dataset = dataProcess().fit_transform_api(url_param_list)
			x = self.get_feature_eval(X,mode=self.parameters.feature_mode)		   
			return x,original_dataset		   

	def generate_feature(self,test_dir=None,mode='train'):
		'''   generate feature for train, validation  or test
		'''  

		if mode == 'train':
			white_dir = self.parameters.train_white
			black_dir = self.patameters.train_black
			X,y = dataProcess().prepare_data_train(white_dir,black_dir) 
			x = self.get_feature_train(X,mode=self.parameters.feature_mode)
			return x,y
		elif mode == 'valid':
			white_dir = self.parameters.eval_white
			black_dir = self.patameters.eval_black
			X,y = dataProcess().prepare_data_train(white_dir,black_dir) 
			x = self.get_feature_eval(X,mode=self.patameters.feature_mode)
			return x,y
		elif mode == 'test':
			if test_dir is None:
				raise RuntimeError('The test data path is not known')
			X,original_dataset = dataProcess().fit_transform(test_dir)
			x = self.get_feature_eval(X,mode=self.parameters.feature_mode)		   
			return x,original_dataset		   
		
	def get_feature_train(self,X,mode='all'):
		''' get feature for training data
		'''
		print('Start extract features for train ...')
		featureArray = None
		if mode == 'all':
			featureTfidf = self.get_tfidf(X)
			featureStatistic = self.get_statistic_feature(X)
			featureArray = np.concatenate((featureTfidf,featureStatistic),axis=1)
		elif mode == 'tfidf':
			featureArray = self.get_tfidf(X)
		elif mode == 'statistic':
			featureArray = self.get_statistic_feature(X)
		print("feature shape is:{}".format(featureArray.shape)) 
		return featureArray

	def get_feature_eval(self,X,mode='all'):
		''' get feature for validation data or test data
			there are three types:tfidf + statistic , tfidf , statistic
		''' 
		#print('Start extract features for evaluation...') 
		featureArray = None
		if mode == 'all':
			transformer = joblib.load(os.path.join(self.parameters.save_dir,'transformer.pkl'))
			featureTfidf = transformer.transform(X).toarray()
			featureStatistic = self.get_statistic_feature(X)
			featureArray = np.concatenate((featureTfidf,featureStatistic),axis=1)
		elif mode == 'tfidf':
			transformer = joblib.load(os.path.join(self.parameters.save_dir,'transformer.pkl'))
			#transformer = joblib.load(self.parameters.save_dir + 'transformer.pkl')
			featureArray = transformer.transform(X).toarray()
		elif mode == 'statistic':
			featureArray = self.get_statistic_feature(X)

		#print("feature shape is:{}".format(featureArray.shape)) 
		return featureArray

	def get_statistic_feature(self,X):
		''' get statistic feature 
			there are six types 
		'''

		function_list = [self.get_len,self.get_url_count,self.get_evil_char,  \
						 self.get_evil_word,self.get_last_char,self.get_entropy] 
		feature_list = []
		for url in X:
			feature_url = []
			for index in self.parameters.feature_usage:
				feature_url += function_list[index](url)
			feature_list.append(feature_url)
		return np.array(feature_list)

	def get_tfidf(self,X):
		''' get tfidf feature
		'''
		
		vocabulary = None
		if self.parameters.vocabulary is not None:
			vocabulary = list(joblib.load(self.parameters.vocabulary).keys())

		transformer = TfidfVectorizer(analyzer = self.parameters.analyzer,ngram_range=self.parameters.ngram,\
										lowercase=self.parameters.lowercase,max_features=self.parameters.max_features,\
										token_pattern=self.parameters.token_tfidf,vocabulary=vocabulary)
		X = transformer.fit_transform(X).toarray()
		#joblib.dump(transformer,self.parameters.save_dir + 'transformer.pkl')
		joblib.dump(transformer,os.path.join(self.parameters.save_dir,'transformer.pkl'))
		joblib.dump(transformer.vocabulary_, os.path.join(self.parameters.save_dir,'transformer-vocabulary.pkl'))
		return X
	 
	''' The following functions are the statistical features,which six types
	'''
	def get_entropy(self,url):
		tmp_dict = {}
		url_length = len(url)
		for letter in url:
			if letter in tmp_dict.keys():
				tmp_dict[letter] += 1
			else:
				tmp_dict.update({letter:1})
		entropy = 0
		for letter in tmp_dict.keys():
			freq = float(tmp_dict[letter] / url_length)
			entropy -= freq*math.log(freq,2)
		return [entropy]

	def get_len(self,url):
		return [len(url)]
	def get_url_count(self,url):
		if re.search('(http://)|(https://)', url, re.IGNORECASE) :
			return [1]
		else:
			return [0]
	def get_evil_char(self,url):
		return [len(re.findall(self.parameters.token_char, url, re.IGNORECASE))]

	def get_evil_word(self,url):
		return [len(re.findall(self.parameters.token_word,url,re.IGNORECASE))]

	def get_evil_word_1(self,url):
		feature = []
		for evil in self.parameters.token_word:
			feature.append(url.count(evil))
		return feature

	def get_last_char(self,url):
		if re.search('/$', url, re.IGNORECASE) :
			return [1]
		else:
			return [0]
