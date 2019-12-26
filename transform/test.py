import math
import random
import pandas as pd
from collections import namedtuple
from utils import regular 
def myiter(d, cols=None):
	if cols is None:
		v = d.values.tolist()
		cols = d.columns.values.tolist()
	else:
		j = [d.columns.get_loc(c) for c in cols]
		v = d.values[:, j].tolist()
 
	n = namedtuple('MyTuple', cols)
 
	for line in iter(v):
		yield n(*line)

df = pd.DataFrame([[1,2,3],[4,5,6]],columns=['A','B','C'])

c = list(myiter(df))
print(regular)
print(c[0].A)

#item_list= ['-',404,200,'404',200]
#item_list= ['-']
#def fillup_unresolved(item_list):
#	 unresolved_num = item_list.count('-')
#	 if unresolved_num == len(item_list):
#		 return item_list
#	 resolved_set = set(item_list) - set('-')
#	 resolved_dict = {x:item_list.count(x) for x in resolved_set}
#	 resolved_keys = list(resolved_dict.keys())
#	 resolved_values = list(resolved_dict.values())
#	 num_range = [sum(resolved_values[0:i+1]) for i,j in enumerate(resolved_values)]
#	 ##构建新的item_list
#	 item_list = list(filter(lambda x:x !='-',item_list))
#	 print(item_list)
#	 for i in range(unresolved_num):
#		 random_num = math.ceil(random.uniform(0,num_range[-1]))
#		 print(random_num)
#		 greater_min = min(list(filter(lambda x:x>=random_num,num_range)))
#		 index = num_range.index(greater_min)
#		 item_list.append(resolved_keys[index])
#	 return item_list
#print(item_list)
#print(fillup_unresolved(item_list))
