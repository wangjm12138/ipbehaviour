###sys layer
import socket
import struct
import time
import math
import Levenshtein
import numpy as np
import pandas as pd
###user layer
import IDS
from utils import check_ip
from utils import check_content
from utils import Configuration 
from utils import MyLogger
config = Configuration()
LOGGER_CONTROL  = MyLogger("Feature_engine",config=config)
LOGGER_CONTROL.disable_file()
LOGGER = LOGGER_CONTROL.getLogger()  


class Feature_engine(object):
#    @check_content
    def __init__(self,http_log_content=None):
        self.http_log_content = http_log_content

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
        #data = data[data['params']]
        data = data[data['status']!='-']
        single = data.drop_duplicates(subset=['src_ip'],keep=False)
        data = data[-data['src_ip'].isin(single['src_ip'])]
        self.http_log_content = data
        return data

#     @check_content
#     def data_preprocess(self,http_log_content=None):
#         if http_log_content is None:
#             df = self.http_log_content
#         data = self.data_clean(input_data)
        

    @check_ip
    def _ipclass(self,ip=None):
        IPclass = ['1.0.0.1','127.0.0.0','127.0.0.0', '191.255.255.254','192.0.1.1',\
                '223.255.255.254','224.0.0.1','239.255.255.254']
        ipint = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip)))[0])
        IP1min,IP1max,IP2min,IP2max,IP3min,IP3max,IP4min,IP4max = \
                    [socket.ntohl(struct.unpack("I",socket.inet_aton(str(item)))[0]) for item in IPclass]
        if ipint > IP1min and ipint <=IP1max:
            return 1
        elif ipint > IP2min and ipint <= IP2max:
            return 2
        elif ipint > IP3min and ipint <= IP3max:
            return 3
        elif ipint > IP4min and ipint <= IP4max:
            return 4
        else:
            return 0
        
    def calcute_entropy(self,item_list):
        H_item = 0
        if len(item_list) != 0:
            item_set = set(item_list)
            P_item = [item_list.count(item)/len(item_list) for item in item_set]
            for i,item in enumerate(item_set):
                 H_item += -1 * P_item[i] * np.log2(P_item[i])
        return H_item
        
    def calcute_ipentropy(self,dest_ip_list):
        """
            calcute entropy
        """
        IP1,IP2,IP3,IP4,other=[],[],[],[],[]
        H_IP1,H_IP2,H_IP3,H_IP4=0,0,0,0
        if len(dest_ip_list) != 0:
            for item in dest_ip_list:
                ipclass = self._ipclass(item)
                if ipclass == 1:
                    IP1.append(item)
                elif ipclass == 2:
                    IP2.append(item)
                elif ipclass == 3:
                    IP3.append(item)
                elif ipclass == 4:
                    IP4.append(item)
                else:
                    other.append(item)
            P_IP1 = len(IP1)/len(dest_ip_list)
            P_IP2 = len(IP2)/len(dest_ip_list)
            P_IP3 = len(IP3)/len(dest_ip_list)
            P_IP4 = len(IP4)/len(dest_ip_list)
            H_IP1,H_IP2,H_IP3,H_IP4 = [-1*item*np.log2(item) if item !=0 \
                                       else 0 for item in [P_IP1,P_IP2,P_IP3,P_IP4]]
            
        return H_IP1,H_IP2,H_IP3,H_IP4
    
    def _http_status_time_method(self,status_list,time_list,method_list):
        new_time,time_interval = [],[]
        time_sec_part,time_us_part,time_us_all = 0.0,0.0,0.0
        H_status = self.calcute_entropy(status_list)
        H_method = self.calcute_entropy(method_list)
        for item in time_list:
            if item != '-' or item is not None:
                time_format = item.split('.')[0]
                time_us_part  = float(item.split('.')[1])
                time_struct = time.strptime(time_format, '%m/%d/%y-%H:%M:%S')
                time_sec_part = time.mktime(time_struct)
                time_us_all = time_sec_part + time_us_part*math.pow(10, -6)
                new_time.append(time_us_all)
        if len(new_time) >1:
            time_interval = [new_time[i+1]-new_time[i] for i in range(len(new_time)-1)]
            mean_time_interval = sum(time_interval)/len(time_interval)
            #print(time_sec_part,time_us_part,)
            H_time_interval = self.calcute_entropy(time_interval)
        elif len(new_time) == 1:
            time_interval = -1
            mean_time_interval = -1
            H_time_interval = -1
        else:
            time_interval = -2
            mean_time_interval = -2
            H_time_interval = -2

        return H_status,H_method,H_time_interval,mean_time_interval

	def url_distance(self,url_df):
        count = 0
		url_list,url_dt = [],[]
		C_similar_url= -1
        if url_df['dest_ip'].nunique() == 1:
            url_list = url_df['params']
            url_dt = [ Levenshtein.distance(url_list[i].lower(),url_list[i+1].lower()) for i \
									in range(len(url_list)) if i!= len(url_list)-1]
            if len(url_dt) == 0:
                C_similar_url = -1
            else:
				C_similar_url = len(list(filter(lambda x:x<5,url_dt)))
        else:
            for i,item in url_df.groupby(['dest_ip']):
                url_list = item['params']
                url_dt =  [ Levenshtein.distance(url_list[i].lower(),url_list[i+1].lower()) for i \
									in range(len(url_list)) if i!= len(url_list)-1]
                if len(url_dt) == 0:
                	C_similar_url += 0
                else:
                    C_similar_url += len(list(filter(lambda x:x<5,url_dt)))

    def webscan_feature(self,input_data=None,ws_ipall=None):
        svm = IDS.SVM()
        if input_data is not None:
            df = input_data
        else:
            df = self.http_log_content
        feature_columns=['P_malicious_urls','C_similar_url','num_404','H_status']
        os_ipset,ws_ipset = set(),set()
        src_ip_set = set(df['src_ip'])
        if ws_ipall is None:
            ws_ipall = []
        else:
            os_ipset = src_ip_set - set(ws_ipall)
            ws_ipset = src_ip_set - os_ipset
        ws_tb = pd.DataFrame(index = list(ws_ipset),columns = feature_columns)
        os_tb = pd.DataFrame(index = list(os_ipset),columns = feature_columns)
        all_tb = pd.DataFrame(index = list(os_ipset),columns = feature_columns)
        for item in src_ip_set:
            src_ip_table = df[df['src_ip'] == item]
            status_list = list(src_ip_table['status'])
            dest_ip_list = list(src_ip_table['dest_ip'])
            url_df = src_ip_table[['params','dest_ip']]
            if len(url_df['dest_ip']) == 1:
                url_list = url_df['params']
                url_dt = [ Levenshtein.distance(url_list[i].lower(),url_list[i+1].lower()) for i \
										in range(len(url_list)) if i!= len(url_list)-1]
				if len(url_dt) == 0:
                    P_malicious_urls = -1
                else:
                    P_malicious_urls = [for item in url_dt if item < 5]
            else:
                for i,item in url_df.groupby(['dest_ip']):
                    url_list = item['params']
                    url_dt =  [ Levenshtein.distance(url_list[i].lower(),url_list[i+1].lower()) for i \
										in range(len(url_list)) if i!= len(url_list)-1]
            num_404 = status_list.count('404')/len(dest_ip_list)
            #result = svm.predict(url_list)
            #P_malicious_urls = len(result[1])/(len(result[0])+len(result[1]))
            H_status = self.calcute_entropy(status_list)
 
            if item in ws_ipall:
                ws_tb['H_status'][item] = H_status
                ws_tb['num_404'][item] = num_404
                ws_tb['P_malicious_urls'][item] = P_malicious_urls
                #ws_tb['mean_time_interval'][item] = mean_time_interval
            else:
                os_tb['H_status'][item] = H_status
                os_tb['num_404'][item] = num_404
                os_tb['P_malicious_urls'][item] = P_malicious_urls
                #os_tb['mean_time_interval'][item] = mean_time_interval       
        all_tb = ws_tb.append(os_tb)
        self.webscan_http_ws_tb = ws_tb
        self.webscan_http_os_tb = os_tb
        self.webscan_http_all_tb = all_tb
        return all_tb,ws_tb,os_tb

#     def dbscan_http_feature(self,ws_ipall=None):
#         """ ws_ipall包含全部网宿云ip，src_ip_set既有包含部分网宿云ip也有包含外部ip
#           src_ip_set-ws_ipall 找出外部的ip
#           src_ip_set - os_ipset 找到网宿云ip
#           七层特征：流数目，不同对端数，平均对端数的流条目，状态码的熵，时间间隔熵，\
#                   平均时间间隔时长，请求方法熵
#        """

#         feature_columns=['flow_num','num_of_peers','mean_flows_per_peer','H_status',\
#                           'H_time_interval','mean_time_interval','H_method']
#         os_ipset,ws_ipset = set(),set()
#         data = self.data_clean()
#         df = data
#         #print(df)
#         src_ip_set = set(df['src_ip'])
#         if ws_ipall is None:
#             ws_ipall = []
#         else:
#             os_ipset = src_ip_set - set(ws_ipall)
#             ws_ipset = src_ip_set - os_ipset
#         ws_tb = pd.DataFrame(index = list(ws_ipset),columns = feature_columns)
#         os_tb = pd.DataFrame(index = list(os_ipset),columns = feature_columns)
#         all_tb = pd.DataFrame(index = list(os_ipset),columns = feature_columns)
#         for item in src_ip_set:
#             src_ip_table = df[df['src_ip'] == item]
#             flow_num = len(src_ip_table['dest_ip'])
#             num_of_peers = len(set(src_ip_table['dest_ip']))
#             mean_flows_per_peer = flow_num/num_of_peers
#             status_list = list(src_ip_table['status'])
#             timestamp_list = list(src_ip_table['timestamp'])
#             method_list = list(src_ip_table['method'])
#             H_status,H_method,H_time_interval,mean_time_interval = \
#                          self._http_status_time_method(status_list,timestamp_list,method_list)
#             if item in ws_ipall:
#                 ws_tb['flow_num'][item] = flow_num
#                 ws_tb['num_of_peers'][item] = num_of_peers
#                 ws_tb['mean_flows_per_peer'][item] = mean_flows_per_peer
#                 ws_tb['H_status'][item] = H_status
#                 ws_tb['H_method'][item] = H_method
#                 #print(H_time_interval)
#                 ws_tb['H_time_interval'][item] = H_time_interval
#                 ws_tb['mean_time_interval'][item] = mean_time_interval
#             else:
#                 os_tb['flow_num'][item] = flow_num
#                 os_tb['num_of_peers'][item] = num_of_peers
#                 os_tb['mean_flows_per_peer'][item] = mean_flows_per_peer
#                 os_tb['H_status'][item] = H_status
#                 os_tb['H_method'][item] = H_method
#                 os_tb['H_time_interval'][item] = H_time_interval
#                 os_tb['mean_time_interval'][item] = mean_time_interval
#         all_tb = ws_tb.append(os_tb)
#         self.dbscan_http_ws_tb = ws_tb
#         self.dbscan_http_os_tb = os_tb
#         self.dbscan_http_all_tb = all_tb
#         return all_tb,ws_tb,os_tb

#     def dbscan_ip4_feature(self,ws_ipall=None):
#         """ws_ipall包含全部网宿云ip，src_ip_set既有包含部分网宿云ip也有包含外部ip
#           src_ip_set-ws_ipall 找出外部的ip
#           src_ip_set - os_ipset 找到网宿云ip
#           四层的特征选取：不同目的IP数，第1~4类IP的熵，平均不同目的IP数所使用的不同源端口数，源端口熵
#           平均不同目的IP数所使用的不同目的端口数，目的端口熵，平均不同目的IP数的流条目。
#         """
#         #feature = None
#         H_IP1,H_IP2,H_IP3,H_IP4 = 0,0,0,0
#         H_srcprt,H_dstprt = 0,0
#         os_ipset,ws_ipset = set(),set()
#         df = self.http_log_content        
#         src_ip_set = set(df['src_ip'])
#         if ws_ipall is None:
#             ws_ipall = []
#         else:
#             os_ipset = src_ip_set - set(ws_ipall)
#             ws_ipset = src_ip_set - os_ipset
#         feature_columns=['num_of_peers','H_IP1','H_IP2','H_IP3','H_IP4','srcprts_per_peers','H_srcprt', \
#                    'dstprts_per_peers','H_dstprt','mean_flows_per_peer'] 
# #                  'num_of_dstprts','H_dstprt','mean_pkts_per_flow','mean_pkts_size','mean_flows_per_peer']
#         ws_tb = pd.DataFrame(index = list(ws_ipset),columns = feature_columns)
#         os_tb = pd.DataFrame(index = list(os_ipset),columns = feature_columns)
#         all_tb = pd.DataFrame(index = list(os_ipset),columns = feature_columns)
#         for item in src_ip_set:
#             src_ip_table = df[df['src_ip'] == item]
#             num_of_peers = len(set(src_ip_table['dest_ip']))
#             num_of_srcprts = len(set(src_ip_table['src_port']))
#             num_of_dstprts = len(set(src_ip_table['dest_port']))
#             srcprts_per_peers = num_of_srcprts/num_of_peers
#             dstprts_per_peers = num_of_dstprts/num_of_peers
#             tmp_dest_ip_list = list(src_ip_table['dest_ip'])
#             tmp_srcprts = list(src_ip_table['src_port'])
#             tmp_dstprts = list(src_ip_table['dest_port'])
#             mean_flows_per_peer = len(tmp_dest_ip_list)/num_of_peers
#             H_IP1,H_IP2,H_IP3,H_IP4 = self.calcute_ipentropy(tmp_dest_ip_list)
#             H_srcprt = self.calcute_entropy(tmp_srcprts)
#             H_dstprt = self.calcute_entropy(tmp_dstprts)
#             if item in ws_ipall:
#                 ws_tb['num_of_peers'][item] = num_of_peers
#                 ws_tb['srcprts_per_peers'][item] = srcprts_per_peers
#                 ws_tb['dstprts_per_peers'][item] = dstprts_per_peers
#                 ws_tb['mean_flows_per_peer'][item] = mean_flows_per_peer
#                 ws_tb['H_IP1'][item] = H_IP1
#                 ws_tb['H_IP2'][item] = H_IP2
#                 ws_tb['H_IP3'][item] = H_IP3
#                 ws_tb['H_IP4'][item] = H_IP4
#                 ws_tb['H_srcprt'][item] = H_srcprt
#                 ws_tb['H_dstprt'][item] = H_dstprt
#             else:
#                 os_tb['num_of_peers'][item] = num_of_peers
#                 os_tb['srcprts_per_peers'][item] = srcprts_per_peers
#                 os_tb['dstprts_per_peers'][item] = dstprts_per_peers
#                 os_tb['mean_flows_per_peer'][item] = mean_flows_per_peer
#                 os_tb['H_IP1'][item] = H_IP1
#                 os_tb['H_IP2'][item] = H_IP2
#                 os_tb['H_IP3'][item] = H_IP3
#                 os_tb['H_IP4'][item] = H_IP4
#                 os_tb['H_srcprt'][item] = H_srcprt
#                 os_tb['H_dstprt'][item] = H_dstprt
#         all_tb = ws_tb.append(os_tb)
#         self.dbscan_ip4_ws_tb = ws_tb
#         self.dbscan_ip4_os_tb = os_tb
#         self.dbscan_ip4_all_tb = all_tb
#         #print(ws_tb)
#         #print(os_tb)
#         return all_tb,ws_tb,os_tb

#     def cblof_feature(self):
#         """
#           从http_log_content生成特征向量，src_dict是字典，key表明每一个源ip，value是字典{不同目的ip：请求数量}。
#           src_dict ={ src_ip1:{dest_ip1:num1,dest_ip2:num2,...},src_ip2:{dest_ip1:num1',dest_ip2:num2',...},...}
#           feature = { src_ip1:[num1,num2...],src_ip2:[num1',num2'...]} 
#         """
#         src_ip_list=list(set(df['src_ip']))
#         dest_ip_list=list(set(df['dest_ip']))        
#         src_dict=dict.fromkeys(src_ip_list)
#         for key in src_dict.keys():
#             src_dict[key]=dict.fromkeys(dest_ip_list,0)
#         for index, row in df.iterrows():
#             src_dict[row['src_ip']][row['dest_ip']]=src_dict[row['src_ip']][row['dest_ip']]+1
#         feature=dict.fromkeys(src_ip_list)
#         for key in feature.keys():
#             feature[key]=[src_dict[key][item] for item in dest_ip_list]
#         self.log_feature=feature
#         self.log_src_dict=src_dict
#         feature = np.array(list(feature.values()))
#         return feature
