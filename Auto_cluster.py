import os
import numpy as np
import pdb
#import matplotlib
#matplotlib.use('tkagg')
#import matplotlib.pyplot as plt
#data,target=datasets.make_classification(n_samples=100, n_features=4, n_informative=2, n_redundant=0,n_repeated=0, n_classes=2, n_clusters_per_class=1)

#sample_list=[[1,2],[0.8,1.9],[0.7,1.9],[1.1,2.2],[1.3,2.1],[10,5],[9.5,4.8],[9.8,4.9],[8.9,4.9],[9.7,4.8]]
#sample=np.array(sample_list)
#plt.scatter(sample[:,0],sample[:,1])
#plt.show()
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
#D=DistMatrix()
#D.Eu_dist_matrix(sample)
#mdist=Eu_dist_matrix(sample)
#print(mdist)

#mdist=np.array([[1,2],[0.8,1.9],[0.7,1.9],[1.1,2.2],[1.3,2.1],[10,5],[8,4.5],[9,4.8],[8.9,9.7],[9.5,4.8]])
#mdist=np.mat(np.random.randint(1,10,size=(10,10)))
class AutoCluster(object):
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

