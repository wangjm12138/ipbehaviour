###sys layer
import re
import socket
import struct
import time
import math
import pickle
import random
import Levenshtein
import numpy as np
import pandas as pd
###user layer
from utils import regular
from utils import check_ip
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
	def __init__(self,http_log_content=None,feature_columns=None):
		self.http_log_content = http_log_content
		if feature_columns is None:
			self.feature_columns = ['Flows','Hostname','Urls','Similar_host',\
						'src_ip','dest_ip',]
		else:
			self.feature_columns = feature_columns

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
		data = data[data['method']!='CONNECT']
		data = data[data['host']!='-']
		#data = data[data['status']!='-']
		data = data[data['dest_ip'].notnull()]
		data = data[data['dest_port'].notnull()]
		#过滤掉只有一条流的源IP,程序先找出不重复的，再用总集-不重复
		#single = data.drop_duplicates(subset=['src_ip'],keep=False)
		#data = data[-data['src_ip'].isin(single['src_ip'])]
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
	
	def Similar_transform(self, url_list, host):
		Similar_host = 0
		pattern = re.compile(regular)
		if len(url_list) == 0:
			return Similar_host
#
#		## url is ip,like url_list=['1.1.1.1','1.1.1.1'],host='1.1.1.1' 
#		ip_list  = [item for item in url_list if pattern.match(item) is not None]
#		if len(ip_list) == len(url_list):
#			Similar_host = float('inf')
#			return Similar_host

		## url contain host,like url_list=['http://baidu.com','http://baidu.com/json/xxx'],host='baidu.com' 
		## host name is not ip
		contain_list = [item for item in url_list if host in item]
		if pattern.match(host) is None and len(contain_list) > 0:
			len_list = list(map(lambda x:len(x),contain_list)) 
			index = len_list.index(min(len_list))
			#Le_d = Levenshtein.distance(url_list[index],host)
			Similar_host = 0
			return Similar_host
		# nomally
		for item in url_list:
			Le_d = Levenshtein.distance(item,host)
			Similar_host += Le_d
		Similar_host = Similar_host/len(url_list)
		return Similar_host

	def extract_feature(self,dest_ip_table):
		result = []
		feature_columns = self.feature_columns
		dest_ip = list(dest_ip_table['dest_ip'])[0]
		host_list = list(dest_ip_table['host']) 
		host_set = set(host_list)
		for item in host_set:
			host_table = dest_ip_table[dest_ip_table['host'] == item]
			url_list = list(host_table['params'])
			src_ip_list = list(host_table['src_ip'])
			Similar_host = self.Similar_transform(url_list,item)
			dic = dict.fromkeys(feature_columns)
			dic['Flows'] = len(host_table)
			dic['Hostname'] = item
			dic['Urls'] = len(set(url_list))
			dic['Similar_host'] = Similar_host
			dic['dest_ip'] = dest_ip
			dic['src_ip'] = src_ip_list
			result.append(dic)

		return result

	def extract_feature_train(self,scan_tb):
		pass

	def domain_feature_train(self,input_data): 
		pass

	def domain_feature(self,input_data=None,ws_ipall=None):
		feature_columns = self.feature_columns
		if input_data is not None:
			df = input_data
		else:
			df = self.http_log_content

		os_ipset,ws_ipset = set(),set()
		dest_ip_set = set(df['dest_ip'])
		if ws_ipall is None:
			ws_ipall = []
		else:
			os_ipset = dest_ip_set - set(ws_ipall)
			ws_ipset = dest_ip_set - os_ipset
		ws_tb = pd.DataFrame(columns = feature_columns)
		os_tb = pd.DataFrame(columns = feature_columns)
		all_tb = pd.DataFrame(columns = feature_columns)
		for item in dest_ip_set:
			dest_ip_table = df[df['dest_ip'] == item]
			features = self.extract_feature(dest_ip_table)
			if item in ws_ipall:
				ws_tb = ws_tb.append(features,ignore_index=True)
			else:
				os_tb = os_tb.append(features,ignore_index=True)
		all_tb = ws_tb.append(os_tb)
		self.webscan_http_ws_tb = ws_tb
		self.webscan_http_os_tb = os_tb
		self.webscan_http_all_tb = all_tb
		return all_tb,ws_tb,os_tb

