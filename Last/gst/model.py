import joblib
import urllib
from multiprocessing import cpu_count

class attack_detection:
	def __init__(self,model_dir):
		self.classifier = joblib.load(model_dir)
		self.classifier.verbose = 0
		self.classifier.n_jobs = cpu_count()
	def fit_predict(self,feature):
		self.y_pred = self.classifier.predict(feature)
		return self.y_pred
		#print(self.y_pred)
	def filter_attckSample(self,original_dataset,save_dir):
		assert self.y_pred is not None
		attackSample = []
		for index,pred in enumerate(self.y_pred):
			if pred != 0:
				data = original_dataset[index]
				attackSample.append(urllib.parse.unquote(data).replace('\n','').replace('\r',''))
		with open(save_dir,'w',encoding='utf-8') as f:
			f.write('\n'.join(attackSample))
	def reset(self):
	   if 'y_pred' in self.__dict__:
		   self.y_pred = None
		
