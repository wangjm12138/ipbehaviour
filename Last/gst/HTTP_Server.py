from utils import generate_path
from flask import Flask,jsonify,request
import json
import os
app = Flask(__name__)

@app.route('/', methods=['GET'])
def get_response():
    return 'Welcome to Web Security Application Platform '

@app.route('/', methods=['POST'])
def apicall():
    test_json = request.get_json()
    params = cheak_url(test_json) 
    if isinstance(params,str):
        return bad_request(params)
    application = params[0]
    option = params[1]
    test_dir = params[2]
    if application == 'attack-detection':
        responses = attack_detection(test_dir,option)
        if isinstance(responses,str):
            os.remove(test_dir)
            return program_error(responses)
    os.remove(test_dir)
    return responses

def attack_detection(test_dir,option):
    resultsDir,logDir = generate_path(test_dir)
    if option == 'prediction':
        cmd = 'python3 /root/webAttackDetection/detection.py ' + test_dir + ' &> ' + logDir
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

@app.errorhandler(400)
def bad_request(error=None):
    message = {'status': 400,'message': error}
    resp = jsonify(message)
    resp.status_code = 400
    return resp

@app.errorhandler(500)
def program_error(error=None):
    message = {'status': 500,'message': error}
    resp = jsonify(message)
    resp.status_code = 500
    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8080)
