import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import time


class loginserver_record():
    def loginserver_record(self):
        print("eyyyyyy")
        url = "http://cs302.kiwi.land/api/get_loginserver_record"



        username = "skmu104"
        password = "skmu104_1392995696"
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }


        payload = {
            
        }
        payload = json.dumps(payload).encode('utf-8')
        print("lol idk")
        try:
            req = urllib.request.Request(url, data = payload,headers=headers)
            print("lmao")
            response = urllib.request.urlopen(req)
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object
