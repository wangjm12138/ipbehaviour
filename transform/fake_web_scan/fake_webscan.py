import os
import socket
import struct
import pandas as pd

filename = "awvs_fake.txt"
dict_keys=['timestamp','xff','protocol','method','host','params', \
				'status','size','src_ip','src_port','dest_ip','dest_port']
ip_init = socket.ntohl(struct.unpack("I",socket.inet_aton(str('1.1.1.1')))[0])
http_log_content = pd.read_table(filename,header=None,sep='\t',index_col=None,names=dict_keys)
new = pd.DataFrame()
num = int(len(http_log_content)/20)

for i in range(num):
	train_tb = http_log_content.loc[i*20:(i+1)*20-1]
	#print(train_tb,type(train_tb))
	train_tb.loc[(train_tb['src_ip'] != 'xxx'),'src_ip'] = socket.inet_ntoa(struct.pack("i", socket.htonl(ip_init+i)))
	new=new.append(train_tb)
new.to_csv('awvs_fake.log', sep='\t', index=False,header=0)
print(new)
