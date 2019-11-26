import socket
import struct
import numpy as np
import pandas as pd
from utils import check_ip
from utils import check_content
from utils import Configuration 
from utils import MyLogger
config = Configuration()
LOGGER_CONTROL  = MyLogger("Feature_engine",config=config)
LOGGER_CONTROL.disable_file()
LOGGER = LOGGER_CONTROL.getLogger()  


class Feature_engine(object):
    @check_content
    def __init__(self,http_log_content=None):
        self.http_log_content = http_log_content

    @property
    def content(self):
        return self.http_log_content

    @content.setter
    @check_content
    def content(self, http_log_content):
        self.http_log_content = http_log_content
 
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

    def calcute_portentropy(self,port_list):
        H_Port = 0
        if len(port_list) != 0:
            port_set = set(port_list)
            P_port = [port_list.count(item)/len(port_list) for item in port_set]
            for i,item in enumerate(port_set):
                 H_Port += -1 * P_port[i] * np.log2(P_port[i])
        return H_Port
        
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


    def dbscan_feature(self,ws_ipall=None):
        """ws_ipall包含全部网宿云ip，src_ip_set既有包含部分网宿云ip也有包含外部ip
          src_ip_set-ws_ipall 找出外部的ip
          src_ip_set - os_ipset 找到网宿云ip
        """
        feature = None
        H_IP1,H_IP2,H_IP3,H_IP4 = 0,0,0,0
        H_srcprt,H_dstprt = 0,0
        df = self.http_log_content        
        src_ip_set = set(df['src_ip'])
        if ws_ipall is None:
            ws_ipall = []
        else:
            os_ipset = src_ip_set - set(ws_ipall)
            ws_ipset = src_ip_set - os_ipset
        feature_columns=['num_of_peers','H_IP1','H_IP2','H_IP3','H_IP4','num_of_srcprts','H_srcprt', \
                   'num_of_dstprts','H_dstprt','mean_flows_per_peer'] 
#                  'num_of_dstprts','H_dstprt','mean_pkts_per_flow','mean_pkts_size','mean_flows_per_peer']
        ws_tb = pd.DataFrame(index = list(ws_ipset),columns = feature_columns)
        os_tb = pd.DataFrame(index = list(os_ipset),columns = feature_columns)
        for item in src_ip_set:
            if item in ws_ipall:
                src_ip_table = df[df['src_ip'] == item]
                num_of_peers = len(set(src_ip_table['dest_ip']))
                num_of_srcprts = len(set(src_ip_table['src_port']))
                num_of_dstprts = len(set(src_ip_table['dest_port']))
                tmp_dest_ip_list = list(src_ip_table['dest_ip'])
                tmp_srcprts = list(src_ip_table['src_port'])
                tmp_dstprts = list(src_ip_table['dest_port'])
                H_IP1,H_IP2,H_IP3,H_IP4 = self.calcute_ipentropy(tmp_dest_ip_list)
                H_srcprt = self.calcute_portentropy(tmp_srcprts)
                H_dstprt = self.calcute_portentropy(tmp_dstprts)
                ws_tb['num_of_peers'][item] = num_of_peers
                ws_tb['num_of_srcprts'][item] = num_of_srcprts
                ws_tb['num_of_dstprts'][item] = num_of_dstprts
                ws_tb['mean_flows_per_peer'][item] = len(tmp_dest_ip_list)/num_of_peers
                ws_tb['H_IP1'][item] = H_IP1
                ws_tb['H_IP2'][item] = H_IP2
                ws_tb['H_IP3'][item] = H_IP3
                ws_tb['H_IP4'][item] = H_IP4
                ws_tb['H_srcprt'][item] = H_srcprt
                ws_tb['H_dstprt'][item] = H_dstprt
        print(ws_tb)
        return feature

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
