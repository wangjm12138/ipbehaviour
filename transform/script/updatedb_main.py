##sys layer
import os
import pdb
import json
import time
from time import ctime
import numpy as np
import pandas as pd
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor
##user layer
from datalib import IPHandle
from utils import Configuration 
from utils import MyLogger
config = Configuration()
LOGGER_CONTROL  = MyLogger("update",config=config,update=True)
LOGGER_CONTROL.disable_file()
LOGGER = LOGGER_CONTROL.getLogger()

PARSER = argparse.ArgumentParser()
## Input Arguments
PARSER.add_argument('--filename','-f',help='filename',type=str,default='http.log')
param, _ = PARSER.parse_known_args()
filename=param.filename


#最大线程个数是10，通过线程池设置
if config.noconf == False:
	Max_threads = config.maxthreads
else:
	Max_threads = 10

def main():
	handle = IPHandle(http_log=filename)
	df = handle.read_http_log()
	threads = []
	dip_list = list(set(df['dest_ip']))

	num_dip = len(dip_list)
	
	starttime = time.time()
	with ThreadPoolExecutor(Max_threads) as executor:
		#线程池默认10，由于O2系统每次最多查询1000个IP，保守起见每个线程只查询100个
		quo,rem = divmod(num_dip,100)
		#print(quo,rem)
		for i in range(0,quo):
			#print(dip_list[i*100:(i+1)*100])
			executor.submit(IPHandle.search_userip,dip_list[i*100:(i+1)*100])
		if rem !=0:
			executor.submit(IPHandle.search_userip,dip_list[quo*100:100*quo+rem])

	
	endtime = time.time()
	LOGGER.info(endtime-starttime)

if __name__ == '__main__':
	main()

