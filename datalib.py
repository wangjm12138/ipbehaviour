import os
import re
import numpy as np
import pandas as pd
import requests
import sqlite3
import json
import base64
import hashlib
import socket
import struct
from feature_engine import Feature_engine
from utils import Configuration 
from utils import MyLogger
config = Configuration()
LOGGER_CONTROL  = MyLogger("IPhandler",config=config)
LOGGER_CONTROL.disable_file()
LOGGER = LOGGER_CONTROL.getLogger()

requests.packages.urllib3.disable_warnings()

IPBEHAVIOUR_DB='ipbehaviour.db'
regular = r'^(((25[0-5]|2[0-4]\d|1\d{2})|([1-9]?\d))\.){3}((25[0-5]|2[0-4]\d|1\d{2})|([1-9]?\d))$'
def check_ip(fuc):
    def wrapper(*args,**kwargs):
        if kwargs.get('ip'):
            ip = kwargs['ip']
        else:
            ip = args[1]
        pattern = re.compile(regular)    
        if isinstance(ip, list):
            for item in ip:
                m = pattern.match(item)
                if m is None:
                    raise ValueError("IP vaild:%s"%item)
            return fuc(*args,**kwargs)
        else:
            #LOGGER.info(ip,type(ip))
            m = pattern.match(ip)
            if m is None:
                raise ValueError("IP vaild:%s"%ip)
            return fuc(*args,**kwargs)
    return wrapper     

class IPHandle(object):

    def __init__(self,http_json = None,http_log = None,even_json = None):
        self.http_json,self.http_log,self.even_json = http_json,http_log,even_json
        self.http_log_main = pd.DataFrame()
        self.http_log_assit = pd.DataFrame()
        self.http_log_content = pd.DataFrame()
        self.dbscan = None
        self.cblof = None

    @classmethod
    @check_ip
    def find_geoip(cls,ip=None,dbinsert=True,dbsearch=True,tbsearch=True):
        """
            geographical表结构:{ip,country,area,region,ciry,county,
                        isp,country_id,area_id,region_id,city_id,county_id,isp_id}
           结构和请求"http://ip.taobao.com/service/getIpInfo.php?ip=%s"的返回值的字段一致
           程序：先查询DB表->成功返回
                      ->item不存在或者db错误->访问淘宝接口(retry次数5)->db正常，插入查询结果并返回
                                                      ->db不正常，返回查询结果
        """
        global IPBEHAVIOUR_DB
        info = {}
        dberror,retry = 0,0
        dbselect_result = []

        select_str = "SELECT * FROM geographical WHERE ip=?"
        insert_main = "INSERT INTO geographical VALUES ('{ip}','{country}','{area}','{region}', \
                                        '{city}','{county}','{isp}','{country_id}','{area_id}', \
                                        '{region_id}','{city_id}','{county_id}','{isp_id}')"
        result = []
        if dbsearch:
            conn = sqlite3.connect(IPBEHAVIOUR_DB)
            cursor = conn.cursor()
            try:
                cursor.execute(select_str,(str(ip),))
                dbselect_result = cursor.fetchone()
            except Exception as e:
                dberror = 1
                LOGGER.info("The ipbehaviour.db select error %s"%(str(e)))
            finally:
                conn.close()

        if (dbsearch == False or dberror or dbselect_result is None or len(dbselect_result) == 0) and tbsearch:
            while retry < 5:
                try:
                    r=requests.get("http://ip.taobao.com/service/getIpInfo.php?ip=%s"%ip)
                    if r.json()['code']==0:
                        info = r.json()['data']
                    break
                except Exception as e:
                    retry = retry+1
            if len(info) != 0 and dberror == 0 and dbinsert and dbsearch:
                insert_str = insert_main.format(**info)
                try:
                    cursor.execute(insert_str)
                    conn.commit()
                except sqlite3.IntegrityError:
                    LOGGER.info("IP %s insert ipbehaviour.db failed,because db already have this item."%(info['ip']))
                finally:
                    conn.close()
                conn.close()
                LOGGER.info("Insert ipbehaviour.db successful!")
                LOGGER.info("From ip.tabao.com:")
            else:
                LOGGER.info("This ip can't get any geographical infomation")
            result = info
        else:
            keys = ('ip','country','area','region','city', \
                    'county','isp','country_id','area_id','region_id','city_id','county_id','isp_id')
            info = dict(zip(keys,dbselect_result))
            LOGGER.info("From ipbehaviour.db:")
            result = info
        return result

    @classmethod
    @check_ip
    def find_userip(cls,ip=None,url=None,certId=None,certKey=None,\
                    dbinsert=True,dbsearch=True,o2search=True,config=None):
        """
            输入参数ip支持列表，dbsearch和o2search的输入参数控制从db查询还是o2查询，从o2查询dbinsert控制是否插入db。
            优先级：当输入参数所有都不为None时候，输入参数>配置文件
            o2接口：
                请求的key-value常用格式：
                "customerIpJson":{"ip":"xxx","queryAll":"0"},
                "certId":"certId",
                "o2Security":base64(sha1("{certId}customerIpJson={"ip"="xxx","queryAll"="0"}{certKey}"))
            程序：先查询DB表->成功返回
            ->item不存在或者db错误->访问O2接口(retry次数5)->db正常，插入查询结果并返回
                                          ->db不正常，返回查询结果
           
        """
        #global cfgpath
        global IPBEHAVIOUR_DB
        dberror,retry = 0,0
        dbitems = []
        dbselect_result = []
        dbselect,dbselect_sub = "",""
        dbselect_main = "SELECT * FROM cloudip WHERE "
        dbinsert = "INSERT INTO cloudip VALUES ('{ipint}','{ip}','{status}','{customerOperateTime}','{operator}', \
                                      '{reportTime}','{dataCenter}','{commodityName}','{customerName}', \
                                     '{consoleAccount}','{isBackUp}','{saleName}','{org}','{phone}')"


        ip_str = ""
        result,result_content = [],[]
        customerIpJson_dict = {}
        ### construct select and insert
        if isinstance(ip, str):
            ipint = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip)))[0])
            dbselect_sub = ' ipint == %s '%(ipint)
            ip_str = ip
        elif isinstance(ip, list):
            ip = list(set(ip))
            ipint = sorted([socket.ntohl(struct.unpack("I",socket.inet_aton(str(item)))[0]) for item in ip])
            dbselect_sub = ' ipint >= %s and ipint <= %s '%(ipint[0],ipint[-1])
            ip_str = ",".join(ip)
        else:
            raise ValueError('Ip type error!')
        ### read from config file
        #conf = configparser.ConfigParser()

        
        if all((url,certId,certKey)) == False and config is not None and config.noconf == False:
            url = config.url
            certId = config.certId
            certKey = config.certKey
        else:
            LOGGER.info("Config file read error!will use default configuration")
            url = "https://172.16.17.87:8001/rms/is/opsReq/getCustomerIpReportList"
            certId = "baseRms"
            certKey = "JExKfYGWjS"

        ### db search
        if dbsearch:
            conn = sqlite3.connect(IPBEHAVIOUR_DB)
            cursor = conn.cursor()
            dbselect = dbselect_main + dbselect_sub

            try:
                cursor.execute(dbselect)
                dbselect_result = cursor.fetchall()
            except Exception as e:
                dberror = 1
                LOGGER.info("The ipbehaviour.db select error %s"%(str(e)))
            finally:
                conn.close()
   
        if (dbsearch == False or dberror or len(dbselect_result) == 0) and o2search:
            customerIpJson_dict['ip'] = ip_str
            customerIpJson_dict["queryAll"] = "0"
            customerIpJson = json.dumps(customerIpJson_dict).replace(" ", "")
            body = {
                'certId':certId,
                'customerIpJson':customerIpJson,
                'o2Security':0
            }
            ### calcute sign
            sign_body ="certId={certId}customerIpJson={customerIpJson}{certKey}".format( \
                certId=certId,customerIpJson=customerIpJson,certKey=certKey)
            sha1 = hashlib.sha1()
            sha1.update(sign_body.encode())
            sign = base64.b64encode(sha1.digest())
            body["o2Security"]=sign.decode()
            headers = {
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                'Connection': 'close'
            }
            #LOGGER.info("data:",body)
            while retry < 5:
                try:
                    res = requests.post(url, verify=False, data=body, headers=headers)
                    res_content = json.loads(res.content)
                    if int(res_content['returnCode']) in [0,-1,-2]:
                        LOGGER.info("request errror: returnCode:%s,0:failed|-1:certId or \
                                o2Security is None| -2 sign is error"%(res_content['returnCode']))
                        break
                    else:
                        result_content = res_content['content']
                        break
                except Exception as e:
                    retry = retry+1
                    if retry == 5:
                        LOGGER.info("Connection retry is achieve 5!")
                        LOGGER.info(e)

            if len(result_content) != 0 and dberror == 0 and dbinsert and dbsearch:
                try:
                    for item in result_content:
                        ipint = socket.ntohl(struct.unpack("I",socket.inet_aton(str(item['ip'])))[0])
                        item['ipint'] = ipint
                        insert_str = dbinsert.format(**item)
                        cursor.execute(insert_str)
                        conn.commit()
                        LOGGER.info("IP %s insert ipbehaviour.db coudip successful!"%(item['ip']))
                except sqlite3.IntegrityError:
                    LOGGER.info("IP %s insert ipbehaviour.db failed,because db already have this item."%(item['ip']))
                finally:
                    conn.close()
                LOGGER.info("From %s:"%(url))
            result = result_content
        else:
            keys = ('ipint','ip','status','customerOperateTime','operator','reportTime','dataCenter' \
                    'commodityName','customerName','consoleAccount','isBackUp','saleName','org','phone')
            if len(dbselect_result) != 0:
                for item in dbselect_result:
                    combine = dict(zip(keys,item))
                    dbitems.append(combine)
                LOGGER.info("From ipbehaviour.db couldip:")
            result = dbitems
        LOGGER.info(result)
        return result

    def feature_engine(self,dbscan=True,cblof=True):
        engine = Feature_engine(self.http_log_content)
        if dbscan:
            conn = sqlite3.connect(IPBEHAVIOUR_DB)
            cursor = conn.cursor()
            select_str = 'select ip from cloudip'
            try:
                cursor.execute(select_str)
                wangsu_iplist = cursor.fetchall()
            except Exception as e:
                LOGGER.info("The ipbehaviour.db select error %s"%(str(e)))
            finally:
                conn.close()
            self.dbscan_feature = engine.dbscan_feature(wangsu_iplist)
        if cblof:
            self.cblof_feature = engine.cblof_feature()
#         return self.dbscan_feature,self.cblof_feature
    
    def read_http_log(self,flag=True):
        """
           http_log_content is transform log -> dataframe type
           every line in log is a row in dataframe type.clumns is [timestamp protocol method host....dest_port]
           timestamp protocol src_ip src_port....dest_port
          0 ..
          1 ..
          2 ..
        """
        src_ip_list=[]
        
        dict_keys=('timestamp','protocol','method','host','params', \
						'status','size','src_ip','src_port','dest_ip','dest_port')
        if self.http_log is None:
            LOGGER.info("No http_log file")
            return
        with open(self.http_log) as f:
            for line in f:
                line_item = line.split()
                timestamp,protocol,method,host,params,status,size,src_ip,src_port,dest_ip,dest_port = line_item
                values = (timestamp,protocol,method,host,params, \
                  status,size,src_ip,src_port,dest_ip,dest_port)
                content = {k:v for k,v in zip(dict_keys,values)}
                self.http_log_content = self.http_log_content.append(content,ignore_index=True)
        return self.http_log_content
#                if flag == True:
#                    if src_ip !=None and src_ip not in src_ip_list:
#                        src_ip_list.append(src_ip)
#                        #LOGGER.info("src_ip:%s"%src_ip) 
#                        src_ip_info = self.find_ip(src_ip)
#                        if len(src_ip_info) == 0:
#                            continue
#                        src_ip_info['src_port']=src_port
#                        #LOGGER.info(src_ip,src_ip_info)
#                        self.http_log_main = self.http_log_main.append(src_ip_info,ignore_index=True)
#                    
#                    #LOGGER.info("dest_ip:%s"%dest_ip)    
#                    dest_ip_info = self.find_ip(dest_ip)
#                    dest_ip_info['src_ip']=src_ip
#                    dest_ip_info['timestamp']=timestamp
#                    dest_ip_info['dest_port']=dest_port
#                    dest_ip_info['host']=[host]
#                    dest_ip_info['params']=[params]
#                    dest_ip_info['status']=[status]
#                    dest_ip_info['size']=[size]
#                    dest_ip_info['method']=[method]
#                    dest_ip_info['flow_num']=1
#                    #LOGGER.info(dest_ip_info)
#                    #LOGGER.info("===========")
#                    self.http_log_assit = self.http_log_assit.append(dest_ip_info,ignore_index=True)
