from .parameters import parameters
from .extractor import extractor
from .model import attack_detection
from .utils import generate_path
import sys
import warnings
warnings.filterwarnings("ignore")

def url_detection_api(url_param_list):
	result = []
	Malics_urls = []
	Sum_xss,Feq_xss = 0,0
	if len(url_param_list)==0:
		return Malics_urls,Sum_xss,Feq_xss
	params = parameters()
	ex = extractor(params)
	X,original_dataset=ex.generate_feature_api(url_param_list)
	classifier = attack_detection(params.model_dir) 
	result = classifier.fit_predict(X)
	classifier.reset()
	Malics_urls = [item for i,item in enumerate(url_param_list) if result[i]==0]
	Sum_xss = sum(result)
	Feq_xss = Sum_xss/len(url_param_list)
	return Malics_urls,Sum_xss,Feq_xss

#url_detection_api(['/KcBO8nQzAsNqRPIj7cLlMQ?op=imageView2&mode=2&width=150&height=150&quality=70&format=jpg',"/DVWA-master/?search=<script>alert(1)</script>"])
