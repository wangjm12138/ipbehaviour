##sys layer
import os
import json
import pdb
import time
import sqlite3
import numpy as np
import pandas as pd
##user layer
import datalib
import feature_engine

starttime = time.time()

filename="scan.log"
filename2="http.log.3"
#filename="nikto.log"
#filename="netspark.log"

## scan dataframe
handle=datalib.IPHandle(http_log=filename)
http_log_content=handle.read_http_log()

wangsu_ip = handle.db_wsip()
engine = feature_engine.Feature_engine(http_log_content)

df = engine.data_clean()

all_tb = engine.webscan_feature_train(input_data=df)
all_tb['label']=1
print(all_tb.sort_values("Sum_xss",inplace=False,ascending=False))
all_tb.to_csv('classfier.txt', sep='\t', index=False)

## nomally dataframe
handle2=datalib.IPHandle(http_log=filename2)
http_log_content2=handle2.read_http_log()

engine2 = feature_engine.Feature_engine(http_log_content2)
df2 = engine2.data_clean()
all_tb2,ws_tb,os_tb = engine2.webscan_feature(input_data=df2)

print(all_tb2.sort_values("Sum_xss",inplace=False,ascending=False))
all_tb2['label']=0

all_tb2.to_csv('classfier.txt', sep='\t', index=False,header=0,mode='a')
