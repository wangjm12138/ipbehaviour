from parameters import parameters
from extractor import extractor
from model import attack_detection
from utils import generate_path
import sys
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def detection(test_dir):
    resultsDir,logDir = generate_path(test_dir)
    params = parameters()
    ex = extractor(params)
    X,original_dataset=ex.generate_feature(test_dir,'test')
    classifier = attack_detection(params.model_dir) 
    print('Start evaluation...')
    classifier.fit_predict(X) 
    classifier.filter_attckSample(original_dataset,resultsDir)
    classifier.reset()
    print('evaluation finish...')
    print('results save in:'+resultsDir)
    print('logs save in:'+logDir)
if __name__ == "__main__":
   
   detection(sys.argv[1])
