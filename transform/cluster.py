# -*- coding: utf-8 -*-
import os
import pdb
import numpy as np
import sklearn.cluster as skc  # 密度聚类
from sklearn import metrics   # 评估模型

class DistMatrix(object):
    def __init__(self):
        self.eu_dist_matrix=None
    def C_eu_dist(self,input_data):
        #print(input_data)
        num,ndim=input_data.shape
        dist_matrix = np.mat(np.zeros([num,num]))
        for i in range(num):
            for j in range(num):
                dist_matrix[i,j] = np.linalg.norm(input_data[i]-input_data[j])
        self.eu_dist_matrix = dist_matrix
        return dist_matrix

class Dbscan(skc.DBSCAN):
	def w(self):
		print(1)


class Autocluster(object):
	def __init__(self,mdist,percent=2):
		if isinstance(mdist,np.matrix) and mdist.ndim==2 \
						and mdist.shape[0] == mdist.shape[1]:
			self.mdist=mdist
			self.percent=percent
			self.utri=np.triu(mdist,1)+np.diag(np.diag(mdist))
		else:
			raise ValueError("Input is dist matrix(type is np.matrix),and is square matrix!")
	def clustering(self):
		N = self.mdist.shape[0]
		percent = self.percent
		mdist = self.mdist
		rho = np.zeros(N)
		position = round(N*percent/100)
		tmp = np.reshape(self.utri,(-1,1))
		utri_l = np.array([item[0] for item in tmp if item >0])
		utri_sl = sorted(utri_l)
		dc = utri_sl[position]

		for i in range(N-1):
			for j in range(i+1,N):
				rho[i] = rho[i] + np.exp(-(mdist[i,j]/dc)**2)
				rho[j] = rho[j] + np.exp(-(mdist[i,j]/dc)**2)

		maxd=np.max(mdist)
		rho_descend=np.array(sorted(rho,reverse=True))
		ordrho=np.argsort(-rho)

		delta=np.zeros(rho_descend.shape[0])
		nneigh=np.zeros(rho_descend.shape[0])
		delta[ordrho[0]]=-1
		delta[ordrho[0]]=0
		for i in range(1,N):
			delta[ordrho[i]]=maxd
			for j in range(0,i):
				#print("mdist[%s,%s]:%s,delta[%s]:%s"%(ordrho[i],ordrho[j],mdist[ordrho[i],ordrho[j]],ordrho[i],delta[ordrho[i]]))
				if mdist[ordrho[i],ordrho[j]] < delta[ordrho[i]]:
					delta[ordrho[i]] = mdist[ordrho[i],ordrho[j]]
					nneigh[ordrho[i]] = ordrho[j]

		delta[ordrho[0]]=max(delta)
		self.rho = rho
		self.delta = delta
		#plt.scatter(self.rho,self.delta)
		#plt.show()

#a=AutoCluster(mdist)
#a.clustering()

