import os
import re
import time
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from .parameters import parameters
import urllib
import base64
argv = parameters()

import logging
import time
import os


class Log(object):
    def __init__(self, logger=None, log_cate='search'):
        self.logger = logging.getLogger(logger)
        self.logger.setLevel(logging.DEBUG)
        self.log_time = time.strftime("%Y_%m_%d")
        file_dir = os.getcwd() + '/../log'
        if not os.path.exists(file_dir):
             os.mkdir(file_dir)
        self.log_path = file_dir
        self.log_name = self.log_path + "/" + log_cate + "." + self.log_time + '.log'
        fh = logging.FileHandler(self.log_name, 'a')
        fh.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(
                    '[%(asctime)s] %(filename)s->%(funcName)s line:%(lineno)d [%(levelname)s]%(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        
        fh.close()
        ch.close()






def base64_decode(url):
    
    pattern = re.compile(r'(?<=base64_decode[(]).*?(?=[)])')
    base64_code = re.findall(pattern,url)
    decode = []
    for code in base64_code:
        code = re.sub(r'[^a-zA-Z0-9/+]+','',code)
        code = code.encode() + b'=' * (-len(code.encode()) % 4)
        code =  base64.decodestring(code)
        decode.append(code.decode())
    for index,code in enumerate(decode):
        url = url.replace(base64_code[index],code)
    return url

def prepare_data_test(test_file_dir):
    X = []
    X_index = []
    pattern1 = re.compile(u"[\u4e00-\u9fa5]+")
    pattern2 = re.compile(r'\d+')
    pattern3 = re.compile(r'(http|https)://[a-zA-Z0-9\.@&#!#\?]+')
    with open(test_file_dir,'r') as f:
        for index,line in enumerate(f):
            line = line.split('?')
            if len(line) > 1 and line[1] != '':
                line = ''.join(line[1:])
                line = urllib.parse.unquote(line)
                line = base64_decode(line)
                line = re.sub(pattern1,'',line)
                line = re.sub(pattern2,'0',line)
                line = re.sub(pattern3,"http://u",line)
                X.append(line.lower().strip('\n'))
                X_index.append(index)
    print('[Test Data status] ...')
    print('[Data status] X length : {}'.format(len(X)))
    return X,X_index


def prepare_data_train(white_dir,black_dir):
    
    white_file_list = []
    black_file_list = []
    pattern1 = re.compile(u"[\u4e00-\u9fa5]+")
    pattern2 = re.compile(r'\d+')
    pattern3 = re.compile(r'(http|https)://[a-zA-Z0-9\.@&#!#\?]+')
    
    with open(white_dir,'r') as f:
        
        for line in f:
            line = urllib.parse.unquote(line)
            line = base64_decode(line)
            line = re.sub(pattern1,'',line)
            line = re.sub(pattern2,'0',line)
            line = re.sub(pattern3,"http://u",line)
            white_file_list.append(line.lower().strip('\n'))
    with open(black_dir,'r') as f:
        for line in f:
            line = urllib.parse.unquote(line)
            line = base64_decode(line) 
            line = re.sub(pattern1,'',line)
            line = re.sub(pattern2,'0',line)
            line = re.sub(pattern3,"http://u",line)
            black_file_list.append(line.lower().strip('\n'))
    len_white_file = len(white_file_list)
    len_black_file = len(black_file_list)

    y_white = [0] * len_white_file
    y_black = [1] * len_black_file
    
    X = white_file_list + black_file_list
    y = y_white + y_black

    print('[Data status] ...')
    print('[Data status] X length : {}'.format(len_white_file + len_black_file))
    print('[Data status] White list length : {}'.format(len_white_file))
    print('[Data status] black list length : {}'.format(len_black_file))
    return X,y



def generate_path(test_path):
    
    father_path = os.path.abspath(os.path.dirname(test_path) + os.path.sep + '.') + '/'
    resultsName = test_path.split('/')[-1].replace('http','results')
    logName = test_path.split('/')[-1].replace('http','logger') 

    return father_path+resultsName,father_path+logName
    
