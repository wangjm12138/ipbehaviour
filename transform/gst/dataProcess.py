import urllib
import base64
import re
class dataProcess:
	def __init__(self):
		self.dataset_get = []
	
	def fit_transform(self,dataset_dir):
		print('Start process data for evaluation')
		self.filter_GET_access(dataset_dir)
		X = self.preprocess()
		return X

	def fit_transform_api(self,url_param_list):
		X = self.preprocess_api(url_param_list)
		return X

	def preprocess_api(self,url_param_list):
		X = []
		for url in url_param_list:
			url = url.split('?')
			url = ''.join(url[1:])
			url = self.url_transform(url)
			X.append(url)
		#print('Dataset length : {}'.format(len(X)))
		return X,url_param_list

	def preprocess(self):
		X = []
		for url in self.dataset_get:
			url = url.split(' ')[5].split('?')
			url = ''.join(url[1:])
			url = self.url_transform(url)
			X.append(url)
		print('Dataset length : {}'.format(len(X)))
		return X,self.dataset_get
	
	def url_transform(self,url):

		pattern1 = re.compile(u"[\u4e00-\u9fa5]+")
		pattern2 = re.compile(r'\d+')
		pattern3 = re.compile(r'(http|https)://[a-zA-Z0-9\.@&#!#\?]+')
		url = urllib.parse.unquote(url)
		url = self.base64_decode(url)
		url = re.sub(pattern1,'',url)
		url = re.sub(pattern2,'0',url)
		url = re.sub(pattern3,"http://u",url)
		return url.lower().strip('\n')

	def filter_GET_access(self,data_dir):
		#self.dataset_get = []
		with open(data_dir,'r') as f:
			for data in f:
				s_data = data.split(' ')
				if s_data[3] == 'GET' and s_data[5] != '-':
					s_data = s_data[5].split('?')
					if len(s_data) > 1 and s_data[1] != '':
						self.dataset_get.append(data)

	def base64_decode(self,url):
	
		pattern = re.compile(r'(?<=base64_decode[(]).*?(?=[)])')
		base64_code = re.findall(pattern,url)
		decode = []
		for code in base64_code:
			code = re.sub(r'[^a-zA-Z0-9/+]+','',code)
			code = code.encode() + b'=' * (-len(code.encode()) % 4)
			code =	base64.decodestring(code)
			decode.append(code.decode())
		for index,code in enumerate(decode):
			url = url.replace(base64_code[index],code)
		return url

	def prepare_data_train(self,white_dir,black_dir):
		
		print('Start preprocess data for train')
		white_file_list = []
		black_file_list = []
		with open(white_dir,'r') as f:
			for url in f:
				url = self.url_transform(url)
				white_file_list.append(url)
		with open(black_dir,'r') as f:
			for url in f:
				url = self.url_transform(url)
				black_file_list.append(url)
		len_white_file = len(white_file_list)
		len_black_file = len(black_file_list)

		y_white = [0] * len_white_file
		y_black = [1] * len_black_file
		X = white_file_list + black_file_list
		y = y_white + y_black
		print('[Data status] ...')
		print('[Data status] Dataset length : {}'.format(len_white_file + len_black_file))
		print('[Data status] White list length : {}'.format(len_white_file))
		print('[Data status] black list length : {}'.format(len_black_file))
		return X,y

 
