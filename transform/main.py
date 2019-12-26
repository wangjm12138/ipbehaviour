##sys layer
import os
import json
import pdb
import time
import numpy as np
import pandas as pd
##user layer
from datalib import IPHandle
from feature_engine2 import Feature_engine
from behaviour import Behaviour
from utils import Configuration 
from utils import MyLogger
config = Configuration()
LOGGER_CONTROL  = MyLogger("main",config=config)
LOGGER_CONTROL.disable_file()
LOGGER = LOGGER_CONTROL.getLogger()

starttime = time.time()

#filename="train/awvs_xss.log"
filename="train/http.log.3"
#filename="train/scan.log"
#filename="train/nikto.log"
#filename="train/netspark.log"
handle = IPHandle(http_log=filename)
handle.read_http_log()

#wangsu_ip = handle.db_wsip()
engine = Feature_engine(handle.http_log_content)

df = engine.data_clean()
all_tb,ws_tb,os_tb = engine.domain_feature(input_data=df)

print(all_tb.sort_values("Flows",inplace=False,ascending=False))
#print(all_tb)

##聚类
#from cluster import Dbscan
#from sklearn import metrics   # 评估模型
#from sklearn import preprocessing
#
#dbscan = Dbscan(eps=1.2, min_samples=10)
#X=all_tb[feature_columns2]
#X=X[X['Feq_404_error']!=-1]
#X=X[X['H_status']!=-1]
#X=X[X['Mean_packets']!=-1]
#
#X_scaled = X[['Sum_flow','Feq_sec_flow','Feq_404_error','H_status','Cls_url','Mean_packets']]
#X_scaled = preprocessing.scale(X_scaled.values)
#
#db = dbscan.fit(X_scaled)
#index = np.array(X.index)
#labels = db.labels_  #和X同一个维度，labels对应索引序号的值 为她所在簇的序号。若簇编号为-1，表示为噪声


##随机森林判别
#behaviour = Behaviour()
#result = behaviour.web_scan(df=all_tb)
#print(result)

endtime = time.time()
print(endtime-starttime)



