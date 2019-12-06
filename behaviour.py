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
from utils import Configuration 
#from utils import check_ip
#from utils import check_content
from utils import Configuration 
from utils import MyLogger
config = Configuration()
LOGGER_CONTROL  = MyLogger("behaviour",config=config)
LOGGER_CONTROL.disable_file()
LOGGER = LOGGER_CONTROL.getLogger()

starttime = time.time()
filename="http.log.3"
handle=datalib.IPHandle(http_log=filename)
handle.read_http_log()

wangsu_ip = handle.get_wsip()
engine = feature_engine.Feature_engine(handle.http_log_content)

df = engine.data_clean()
all_tb,ws_tb,os_tb = engine.webscan_feature(input_data=df[:100],ws_ipall=wangsu_ip)
print(all_tb)

endtime = time.time()
print(endtime-starttime)



