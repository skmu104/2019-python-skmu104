import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import time



class report():
    
    def report(self,username,password,publicKey):
        url = "http://cs302.kiwi.land/api/report"
        ip = "10.103.137.255"
        

        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "connection_address" : ip,
            "connection_location" : 1,
            "incoming_pubkey" : publicKey,
            "status" : "online"

        }
        payload = json.dumps(payload).encode('utf-8')
        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read() # read the received bytes
            #asking the data set
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        
        #ayload = json.dumps(payload).encode('utf-8')