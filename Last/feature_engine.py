###sys layer
import socket
import struct
import time
import math
import pickle
import random
#import Levenshtein
import numpy as np
import pandas as pd
###user layer
from utils import check_ip
from utils import check_content
from utils import Configuration 
from utils import MyLogger
from gst.detection_api import url_detection_api
config = Configuration()
LOGGER_CONTROL	= MyLogger("Feature_engine",config=config)
LOGGER_CONTROL.disable_file()
LOGGER = LOGGER_CONTROL.getLogger()  


class Feature_engine(object):
#	 @check_content
	def __init__(self,http_log_content=None):
		self.http_log_content = http_log_content
		ac_tree = './ac/dir_traver.pkl'
		with open(ac_tree,'br') as f:
			self.dir_traver_ac = pickle.load(f)
		#self.feature_columns=['Sum_sec_flow','Feq_sec_flow','Sum_xss','Feq_xss','Sum_dir','Feq_dir',\
		#				'Sum_404_error','Feq_404_error','H_status','src_ip','dest_ip','Malics_urls']
		self.feature_columns=['Sum_sec_flow','Feq_sec_flow','Sum_xss','Feq_xss','Sum_dir','Feq_dir',\
						'Sum_404_error','Feq_404_error','H_status','Cls_url','Sum_packets','Mean_packets',\
						'src_ip','dest_ip','Malics_urls',]

	@property
	def content(self):
		return self.http_log_content

	@content.setter
	@check_content
	def content(self, http_log_content):
		self.http_log_content = http_log_content

	def data_clean(self,input_data=None):
		if input_data is not None:
			data = input_data
		else:
			data = self.http_log_content
		#过滤掉nids没有解析的字段的条目
		data = data[data['protocol']!='-']
		data = data[data['method']!='-']
		#data = data[data['status']!='-']
		data = data[data['dest_ip'].notnull()]
		data = data[data['dest_port'].notnull()]
		#过滤掉只有一条流的源IP,程序先找出不重复的，再用总集-不重复
		single = data.drop_duplicates(subset=['src_ip'],keep=False)
		data = data[-data['src_ip'].isin(single['src_ip'])]
		self.http_log_content = data
		return data

#	@check_content
#	def data_preprocess(self,http_log_content=None):
#		if http_log_content is None:
#			df = self.http_log_content
#		data = self.data_clean(input_data)

	def calcute_entropy(self,item_list):
		H_item = 0
		if len(item_list) != 0:
			item_set = set(item_list)
			P_item = [item_list.count(item)/len(item_list) for item in item_set]
			for i,item in enumerate(item_set):
				 H_item += -1 * P_item[i] * np.log2(P_item[i])
		return H_item

	def time_transform(self,timestamp_list):
		"""
			返回1秒源ip访问流条目占总流条目占比，由于日志是精确到微妙->1/20/19-19:03:00.698841
			如果只算秒，源ip访问其中一个目的ip的时间(秒)例如如下:
			[1/20/19-19:03:00,1/20/19-19:03:01,1/20/19-19:03:01,1/20/19-19:03:02,1/20/19-19:03:02]
			转换时间戳:
			[t1,t2,t2,t3,t3],函数将返回4/5，因为在1秒内有两个t2，两个t3,5条流
		"""
		sec_time_list = []
		Sum_sec_flow,Feq_sec_flow = 0,0
		for item in timestamp_list:
			if item != '-' or item is not None:
				time_format = item.split('.')[0]
				time_struct = time.strptime(time_format, '%m/%d/%y-%H:%M:%S')
				time_sec_part = time.mktime(time_struct)
				sec_time_list.append(time_sec_part)
		one_sec_flow = list(map(lambda x:sec_time_list.count(x)-1,list(set(sec_time_list))))
		if len(timestamp_list) == 0:
			Feq_sec_flow  = 0
			Sum_sec_flow  = 0
		elif len(timestamp_list) == 1:
			Feq_sec_flow  = 1
			Sum_sec_flow  = 1
		else:
			Sum_sec_flow = sum(list(map(lambda x:x+1 if x!=0 else 0,one_sec_flow)))
			Feq_sec_flow = Sum_sec_flow/len(timestamp_list)	   
		return Sum_sec_flow,Feq_sec_flow

	def dir_traver_transform(self,url_list):
		Sum_dir,Feq_dir = 0,0
		for url in url_list:
			l_match = [match for match in self.dir_traver_ac.iter(url)]
			if len(l_match) > 0:
				Sum_dir = Sum_dir + 1
		if len(url_list) !=0:
			Feq_dir = Sum_dir/len(url_list)
		return Sum_dir,Feq_dir

	def status_transform(self,status_list):
		"""status_list由于有没解析的部分'-'，所以按照原先一定概率补全没解析的
			例如status_list = ['200','200','404','-','302']
			其中200有2个，404一个，302一个，则'-'，有50%概率是200，20%是404或者302
		"""
		Sum_404_error,Feq_404_error,H_status = 0,0,0
		
		unresolved_num = status_list.count('-')
		if unresolved_num == len(status_list):
			Sum_404_error = -1	
			Feq_404_error = -1	
			H_status = -1
			return Sum_404_error,Feq_404_error,H_status
		resolved_set = set(status_list) - set('-')
		resolved_dict = {x:status_list.count(x) for x in resolved_set}
		resolved_keys = list(resolved_dict.keys())
		resolved_values = list(resolved_dict.values())
		num_range = [sum(resolved_values[0:i+1]) for i,j in enumerate(resolved_values)]
		##构建新的status_list
		status_list = filter(lambda x:x =='-',status_list)
		for i in range(unresolved_num):
			random_num = random.uniform(0,num_range[-1])
			status_list.append()
		
		str_404 = status_list.count('404')
		int_404 = status_list.count(404)
		if str_404 > int_404:
			Sum_404_error = str_404
		else:
			Sum_404_error = int_404
		if len(status_list)!=0:
			Feq_404_error = Sum_404_error/len(status_list)

		H_status = self.calcute_entropy(status_list)
		return Sum_404_error,Feq_404_error,H_status

	def extract_feature(self,src_ip_table):
		result = []
		feature_columns = self.feature_columns
		src_ip = list(src_ip_table['src_ip'])[0] 
		if src_ip_table['dest_ip'].nunique() == 1:
			timestamp_list = list(src_ip_table['timestamp'])
			status_list = list(src_ip_table['status'])
			url_df = src_ip_table[src_ip_table['method']=='GET']
			url_list = list(url_df['params'])
			dest_ip = list(src_ip_table['dest_ip'])[0]

			Malics_urls,Sum_xss,Feq_xss = url_detection_api(url_list)
			Sum_dir,Feq_dir = self.dir_traver_transform(url_list)
			Sum_sec_flow,Feq_sec_flow = self.time_transform(timestamp_list)
			Sum_404_error,Feq_404_error,S_Hstatus = self.status_transform(status_list)
			dic = dict.fromkeys(feature_columns)
			dic['Feq_sec_flow'] = Feq_sec_flow
			dic['Sum_sec_flow'] = Sum_sec_flow
			dic['Sum_404_error'] = Sum_404_error
			dic['Feq_404_error'] = Feq_404_error
			dic['H_status'] = S_Hstatus
			dic['src_ip'] = src_ip 
			dic['dest_ip'] = dest_ip
			dic['Sum_xss'] = Sum_xss
			dic['Feq_xss'] = Feq_xss
			dic['Sum_dir'] = Sum_dir
			dic['Feq_dir'] = Feq_dir
			#dic['Malics_urls'] = Malics_urls
			result.append(dic)
		else:
			for dest_ip,item in src_ip_table.groupby(['dest_ip']):
				url_df = item[item['method']=='GET']
				url_list = list(url_df['params'])
				timestamp_list = list(item['timestamp'])
				status_list = list(item['status'])
				Malics_urls,Sum_xss,Feq_xss = url_detection_api(url_list)
				Sum_dir,Feq_dir = self.dir_traver_transform(url_list)
				Sum_sec_flow,Feq_sec_flow = self.time_transform(timestamp_list)
				Sum_404_error,Feq_404_error,H_status = self.status_transform(status_list)
				dic = dict.fromkeys(feature_columns)
				dic['Feq_sec_flow'] = Feq_sec_flow
				dic['Sum_sec_flow'] = Sum_sec_flow
				dic['Sum_404_error'] = Sum_404_error
				dic['Feq_404_error'] = Feq_404_error
				dic['H_status'] = H_status
				dic['src_ip'] = src_ip
				dic['dest_ip'] = dest_ip
				dic['Sum_xss'] = Sum_xss
				dic['Feq_xss'] = Feq_xss
				dic['Sum_dir'] = Sum_dir
				dic['Feq_dir'] = Feq_dir
				#dic['Malics_urls'] = Malics_urls
				result.append(dic)
		return result

	def extract_feature_train(self,scan_tb):
		feature_columns = self.feature_columns
		index = 0
		result = []
		#scan_tb.sample(frac=1)
		num = int(len(scan_tb)/20)

		for i in range(num):
			train_tb = scan_tb.loc[i*20:(i+1)*20-1]
			timestamp_list = list(train_tb['timestamp'])
			status_list = list(train_tb['status'])
			url_df = train_tb[train_tb['method']=='GET']
			url_list = list(url_df['params'])
			#dest_ip = list(train_tb['dest_ip'])[0]

			Malics_urls,Sum_xss,Feq_xss = url_detection_api(url_list)
			Sum_dir,Feq_dir = self.dir_traver_transform(url_list)
			Sum_sec_flow,Feq_sec_flow = self.time_transform(timestamp_list)
			Sum_404_error,Feq_404_error,S_Hstatus = self.status_transform(status_list)
			dic = dict.fromkeys(feature_columns)
			dic['Feq_sec_flow'] = Feq_sec_flow
			dic['Sum_sec_flow'] = Sum_sec_flow
			dic['Sum_404_error'] = Sum_404_error
			dic['Feq_404_error'] = Feq_404_error
			dic['H_status'] = S_Hstatus
			#dic['src_ip'] = src_ip 
			#dic['dest_ip'] = dest_ip
			dic['Sum_xss'] = Sum_xss
			dic['Feq_xss'] = Feq_xss
			dic['Sum_dir'] = Sum_dir
			dic['Feq_dir'] = Feq_dir
			#dic['Malics_urls'] = Malics_urls
			result.append(dic)
		return result

	def webscan_feature_train(self,input_data): 
		feature_columns = self.feature_columns
		if input_data is not None:
			df = input_data
		else:
			df = self.http_log_content
		all_tb = pd.DataFrame(columns = feature_columns)
		features = self.extract_feature_train(df)
		
		all_tb = all_tb.append(features,ignore_index=True)
		self.webscan_train_all_tb = all_tb
		return all_tb

	def webscan_feature(self,input_data=None,ws_ipall=None):
		feature_columns = self.feature_columns
		if input_data is not None:
			df = input_data
		else:
			df = self.http_log_content
		os_ipset,ws_ipset = set(),set()
		src_ip_set = set(df['src_ip'])
		if ws_ipall is None:
			ws_ipall = []
		else:
			os_ipset = src_ip_set - set(ws_ipall)
			ws_ipset = src_ip_set - os_ipset
		ws_tb = pd.DataFrame(columns = feature_columns)
		os_tb = pd.DataFrame(columns = feature_columns)
		all_tb = pd.DataFrame(columns = feature_columns)
		for item in src_ip_set:
			src_ip_table = df[df['src_ip'] == item]
			features = self.extract_feature(src_ip_table)
			if item in ws_ipall:
				ws_tb = ws_tb.append(features,ignore_index=True)
			else:
				os_tb = os_tb.append(features,ignore_index=True)
		all_tb = ws_tb.append(os_tb)
		self.webscan_http_ws_tb = ws_tb
		self.webscan_http_os_tb = os_tb
		self.webscan_http_all_tb = all_tb
		return all_tb,ws_tb,os_tb

