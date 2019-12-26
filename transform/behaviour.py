import os
import pickle

class Behaviour(object):

	def __init__(self,df_features=None):
		self.df = df_features
		self.result = None
		model = './model/random_forest.pkl'
		with open(model,'rb') as f:
			self.web_scan_model = pickle.load(f)
		self.feature_columns = ['Sum_sec_flow','Feq_sec_flow',\
						'Feq_xss','Feq_dir','Feq_404_error','H_status']

	def identification(self,src_ip_table):
		y_pred = src_ip_table[self.feature_columns]
		preds = self.web_scan_model.predict(y_pred)
		return preds

	def web_scan(self,df=None):
		if df is None:
			df = self.df_features
		src_ip_set = set(df['src_ip'])
		for item in src_ip_set:
			columns = list(df['src_ip'] == item)
			src_ip_table = df[columns]
			preds = self.identification(src_ip_table)
			rows =[i for i,item in enumerate(columns) if item==True]
			df.loc[rows,'web_scan'] = preds
		self.result = df
		return df
