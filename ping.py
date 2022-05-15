import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import time

class ping():

    def ping(self,publicKey,signing_key):
        url = "http://cs302.kiwi.land/api/ping"

        username = "skmu104"
        password = "skmu104_1392995696"


        # hex_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
        # signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)
        # print(hex_key)

        # verify_key = signing_key.verify_key

        # verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

        # pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        # pubkey_hex_str = pubkey_hex.decode('utf-8')

        #signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        #signature_hex_str = signed.signature.decode('utf-8')

        #ping.ping(self,pubkey_hex_str,signature_hex_str,username,password)
        message_bytes = bytes(publicKey, encoding='utf-8')

        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "pubkey" : publicKey,
            "signature" : signature_hex_str
        }

        payload = json.dumps(payload).encode('utf-8')

        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
