import pandas as pd
# from utils import Configuration 
# from utils import MyLogger
# config = Configuration()
# LOGGER_CONTROL  = MyLogger("Feature_engine",config=config)
# LOGGER_CONTROL.disable_file()
# LOGGER = LOGGER_CONTROL.getLogger()

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


class Feature_engine(object):
    def __init__(self,http_log_content=None):
        #print(http_log_content)
        if type(http_log_content) == pd.core.frame.DataFrame:
            if http_log_content is None or len(http_log_content)==0:
                raise ValueError("http_log_content is empty or not !")
        else:
            raise TypeError('http_log_content type error!')
        self.http_log_content = http_log_content

    def calcute_entropy(self,srcip_table):
        if 
    
    def dbscan_feature(self,wangsu_iplist):
        print(wangsu_iplist)
        df = self.http_log_content
        src_ip_list=list(set(df['src_ip']))
        feature_list=['num_of_peers','H_IP1/4','H_IP2/4','H_IP3/4','num_of_srcprts','H_srcprt' \
                  'num_of_dstprts','H_dstprt','mean_pkts_per_flow','mean_pkts_size','mean_flows_per_peer']       
        src_dict=dict.fromkeys(src_ip_list)
        for key in src_dict.keys():
            src_dict[key]=dict.fromkeys(feature_list,0)
        for item in src_ip_list:
            src_ip_table = df[df['src_ip']==item]
            src_dict[item]['num_of_peers'] = len(set(src_ip_table['dest_ip']))
            src_dict[]
            

        return feature

    def cblof_feature(self):
        """
          从http_log_content生成特征向量，src_dict是字典，key表明每一个源ip，value是字典{不同目的ip：请求数量}。
          src_dict ={ src_ip1:{dest_ip1:num1,dest_ip2:num2,...},src_ip2:{dest_ip1:num1',dest_ip2:num2',...},...}
          feature = { src_ip1:[num1,num2...],src_ip2:[num1',num2'...]} 
        """
        src_ip_list=list(set(df['src_ip']))
        dest_ip_list=list(set(df['dest_ip']))        
        src_dict=dict.fromkeys(src_ip_list)
        for key in src_dict.keys():
            src_dict[key]=dict.fromkeys(dest_ip_list,0)
        for index, row in df.iterrows():
            src_dict[row['src_ip']][row['dest_ip']]=src_dict[row['src_ip']][row['dest_ip']]+1
        feature=dict.fromkeys(src_ip_list)
        for key in feature.keys():
            feature[key]=[src_dict[key][item] for item in dest_ip_list]
        self.log_feature=feature
        self.log_src_dict=src_dict
        feature = np.array(list(feature.values()))
        return feature
