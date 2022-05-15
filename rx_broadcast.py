import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import time


class rx_broadcast():
    
    def rx_broadcast(self,login_record,signing_key,publicKey,message):
        url = "http://cs302.kiwi.land/api/rx_broadcast"
        username = "skmu104"
        password = "skmu104_1392995696"

        #message = "h"
        #t = time()

        print(login_record)
        login = login_record['loginserver_record']
        tim = str(time.time())
        message_bytes = bytes(login+ message + tim, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        sig_hex_str = signed.signature.decode('utf-8')

        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record" : login,
            "message" : message,
            "sender_created_at" : tim,# tim,
            "signature" : sig_hex_str

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