##sys layer
import os
import json
import pdb
import time
import numpy as np
import pandas as pd
##user layer
from datalib import IPHandle
from feature_engine import Feature_engine
from behaviour import Behaviour
from utils import Configuration 
#from utils import check_ip
#from utils import check_content
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
all_tb,ws_tb,os_tb = engine.webscan_feature(input_data=df)

print(all_tb.sort_values("Sum_xss",inplace=False,ascending=False))

behaviour = Behaviour()
result = behaviour.web_scan(all_tb)


print(result.sort_values("web_scan",inplace=False,ascending=False))

endtime = time.time()
#print(endtime-starttime)



