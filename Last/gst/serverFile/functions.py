from flask import jsonify,request
from utils import generate_path
def attack_detection(test_dir,option):
    resultsDir,logDir = generate_path(test_dir)
    if option == 'prediction':
        cmd = 'python detection.py ' + test_dir + ' &> ' + logDir
        code = os.system(cmd)
        if code != 0:
            error = 'bad request: ' + request.url + \
                    '--> Program running error...'
            return error 
    res = {"results":resultsDir,"logs":logDir}
    responses = jsonify(res)
    responses.status_code = 200
    return responses

def cheak_url(test_json):
    applications = ['attack-detection']
    options = ['prediction','results']
    try:
        application = test_json['application']
        option = test_json['option']
        test_dir = test_json['dataPath']
        if os.path.isfile(test_dir) \
            and application in applications \
            and option in options:
            return [application,option,test_dir]
        else:
            error = 'bad request: ' + request.url + \
                    '--> please check your json structure or data path...'
            return error

    except:
        error = 'Bad Request: ' + request.url + \
                '--> Please check your json structure or data path...'
        return error

