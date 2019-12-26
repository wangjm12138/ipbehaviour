import requests
import json
import sys
def main(argv):
    
    server_address = argv[1]
    application = argv[2]
    option = argv[3]
    dataPath = argv[4]
    
    message = {'application':application,'option':option,'dataPath':dataPath}
    message = json.dumps(message)
    header = {'Content-Type': 'application/json','Accept': 'application/json'}
    resp = requests.post(server_address,message,headers=header)

    print('response informations \nstatus:{} \ncontents:{}'.format(resp.status_code,    \
                                                                   resp.content.decode()))


if __name__ == '__main__':

    main(sys.argv)
   

