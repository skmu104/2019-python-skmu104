import urllib.request
import json
import base64
import nacl.signing
import nacl.encoding
import time
import nacl.secret
import nacl.pwhash
import nacl.utils
from nacl.public import SealedBox
import nacl.secret
import nacl.utils
import socket
import nacl.hash
from bs4 import BeautifulSoup


def ping(self,publicKey,signing_key,username,apiKey):
        url = "http://cs302.kiwi.land/api/ping"

        m_bytes = bytes(publicKey, encoding='utf-8')

        signed = signing_key.sign(m_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')


        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username' : username,
            'X-apikey': apiKey,
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
            data = response.read() 
            encoding = response.info().get_content_charset('utf-8') 
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
     

def add_pubkey(self,username,apiKey):
        url = "http://cs302.kiwi.land/api/add_pubkey"


        
        pri_key = nacl.signing.SigningKey.generate().encode(encoder=nacl.encoding.HexEncoder)
        signing_key = nacl.signing.SigningKey(pri_key, encoder=nacl.encoding.HexEncoder)

        verify_key = signing_key.verify_key

        verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)

        pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)

        pubkey_hex_str = pubkey_hex.decode('utf-8')

        message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')

        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username' : username,
            'X-apikey': apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "pubkey" : pubkey_hex_str,
            "username" : username,
            "signature" : signature_hex_str

        }
        payload = json.dumps(payload).encode('utf-8')

        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read() 
            encoding = response.info().get_content_charset('utf-8') 
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        
        return pubkey_hex_str,signature_hex_str,pri_key,signing_key

def report(self,username,apiKey,publicKey,status = "online"):
        url = "http://cs302.kiwi.land/api/report"
        
        listening_ip = socket.gethostbyname(socket.gethostname())



        ip = ""+listening_ip+":"+"10050"
 

        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username' : username,
            'X-apikey': apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }
       

        payload = {
            "connection_address" : ip,
            "connection_location" : 0,
            "incoming_pubkey" : publicKey,
            "status" : status

        }
        payload = json.dumps(payload).encode('utf-8')
        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read() 
            encoding = response.info().get_content_charset('utf-8') 
            response.close()
        except urllib.error.HTTPError as error: 
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        

def rx_broadcast(self,login_record,signing_key,publicKey,message,username,apiKey,url):

        url = "http://"+url+"/api/rx_broadcast"

        login = login_record['loginserver_record']
        tim = str(time.time())
        message_bytes = bytes(login+ message + tim, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        sig_hex_str = signed.signature.decode('utf-8')

        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username' : username,
            'X-apikey': apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record" : login,
            "message" : message,
            "sender_created_at" : tim,
            "signature" : sig_hex_str

        }
        payload = json.dumps(payload).encode('utf-8')

        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
    
            response = urllib.request.urlopen(req,timeout=1)
            
            data = response.read() 
        
            encoding = response.info().get_content_charset('utf-8') 
            response.close()
          
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)

def loginserver_record(self,username,apiKey):
        url = "http://cs302.kiwi.land/api/get_loginserver_record"




        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username' : username,
            'X-apikey': apiKey,
            'Content-Type' : 'application/json; charset=utf-8',
        }


        payload = {
            
        }
        payload = json.dumps(payload).encode('utf-8')
        
        try:
            req = urllib.request.Request(url, data = payload,headers=headers)
            print("lmao")
            response = urllib.request.urlopen(req)
            data = response.read() 
            encoding = response.info().get_content_charset('utf-8') 
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
       
        return JSON_object

def list_users(self,username,apiKey):
    url = "http://cs302.kiwi.land/api/list_users"

    user_list = []



    headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'X-username' : username,
        'X-apikey': apiKey,
        'Content-Type' : 'application/json; charset=utf-8',
    }


    payload = {
            
    }
    payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data = payload,headers=headers)
        print("lmao")
        response = urllib.request.urlopen(req)
        data = response.read() 
        encoding = response.info().get_content_charset('utf-8') 
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))

    return JSON_object


def check_pubkey(self,publicKey,username,apiKey):

    url = "http://cs302.kiwi.land/api/check_pubkey"

    headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'X-username' : username,
        'X-apikey': apiKey,
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey": "bd03800cf2134b43360155c5eaa92e9a19422619686ed4230a3be7f4850a8ca9"
    }

    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data = payload,headers= headers)

        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    pub = JSON_object['incoming_pubkey']
    print(JSON_object)
    return pub


def loginserver_pubkey(self):

    url = "http://cs302.kiwi.land/api/loginserver_pubkey"

    headers = {
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
    }

    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data = payload,headers=headers)

        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    
    return JSON_object['pubkey']


def sBoxKey(self,password):

    pass_byte = bytes(password, encoding='utf-8')



    text = "huhuhu"

    priv_JSON = {
        "message": text

    }
    priv_JSON = json.dumps(priv_JSON)

    message = bytes(priv_JSON,encoding= 'utf-8')


    kdf = nacl.pwhash.argon2i.kdf


    salt_size = nacl.pwhash.argon2i.SALTBYTES 


    salt = pass_byte * 16
 
    salt_byte = salt[:16]



    key = kdf(nacl.secret.SecretBox.KEY_SIZE, pass_byte, salt_byte)

    secret_box = nacl.secret.SecretBox(key)

    
    p_data = secret_box.encrypt(message)

    data = base64.b64encode(p_data).decode("ascii")
    
    return data




def decrypt_message(self,p_data,password):
    pass_byte = bytes(password, encoding='utf-8')
    kdf = nacl.pwhash.argon2i.kdf

    salt_size = nacl.pwhash.argon2i.SALTBYTES 

    salt = pass_byte * 16
    salt_byte = salt[:16]

    key = kdf(nacl.secret.SecretBox.KEY_SIZE, pass_byte, salt_byte,nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE)

    secret_box = nacl.secret.SecretBox(key)


    disp = secret_box.decrypt(p_data,encoder=nacl.encoding.Base64Encoder)
    mes = (disp.decode("utf-8"))

    mes = json.loads(mes)
    

    return mes





def load_new_apikey(self,username,password):

    url = "http://cs302.kiwi.land/api/load_new_apikey"

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))

    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
    }

    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data = payload,headers=headers)

        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    
    

    return JSON_object['api_key'],JSON_object['response']


def ping_check(self,url):


    headers = {
         
        'Content-Type' : 'application/json; charset=utf-8',
    }
    listening_ip = socket.gethostbyname(socket.gethostname())


        
    ip = ""+listening_ip+":"+"10050"

    cur_time = str(time.time())
    user_list = [""]
    
    payload = {
        "my_time":cur_time,
        "my_active_usernames":user_list,
        "connection_address":ip,
        "connection_location":0

    }
    payload = json.dumps(payload).encode('utf-8')
    try:
      
        req = urllib.request.Request(url, data = payload,headers=headers)
    
        response = urllib.request.urlopen(req,timeout=0.01)
        
        data = response.read() 
        encoding = response.info().get_content_charset('utf-8') 
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)



def add_privatedata(self,username,apiKey,password,loginserver,signing_key,JSON_p,prikeys="",b_pubs=[],b_users=[],b_words=[],b_mes_sig=[],fav_mes_sig=[],f_users=[]):
    url = "http://cs302.kiwi.land/api/add_privatedata"

    headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'X-username' : username,
        'X-apikey': apiKey,
        'Content-Type' : 'application/json; charset=utf-8',
    }




    p_data = privateData(self,password,JSON_p,prikeys,b_pubs,b_users,b_words,b_mes_sig,fav_mes_sig,f_users)


    save_time = str(time.time())

 
    login = loginserver['loginserver_record']
    message_bytes = bytes(p_data + login + save_time, encoding='utf-8')

    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    payload = {
        "privatedata":p_data,
        "loginserver_record": login,
        "client_saved_at":save_time,
        "signature":signature_hex_str
            
    }
    payload = json.dumps(payload).encode('utf-8')

    try:
      
        req = urllib.request.Request(url, data = payload,headers=headers)

        response = urllib.request.urlopen(req)
        data = response.read()
        encoding = response.info().get_content_charset('utf-8') 
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)

def privateData(self,password,JSON_p,prikeys = [],b_pubs = None,b_users = None,b_words=None,b_mes_sig= None,fav_mes_sig=None,f_users=None):





    priv_JSON = {

        "prikeys":[prikeys],
        "blocked_pubkeys":JSON_p["blocked_pubkeys"],# JSON_p['blocked_pubkeys'].append(b_pubs),
        "blocked_usernames":JSON_p["blocked_usernames"],# JSON_p['blocked_usernames'].append(b_users),
        "blocked_words":JSON_p["blocked_words"],#JSON_p['blocked_words'].append(b_words),
        "blocked_message_signatures":JSON_p["blocked_message_signatures"],#JSON_p['blocked_message_signatures'].append(b_mes_sig),
        "favourite_message_signatures":JSON_p["favourite_message_signatures"],#JSON_p['favourite_message_signatures'].append(fav_mes_sig),
        "friends_usernames":JSON_p["friends_usernames"],#JSON_p['friends_usernames'].append(f_users)
        "group_key": JSON_p["group_key"],
    }
    if f_users == []:
        pass
    else:
        priv_JSON["friends_usernames"].append(f_users)
    if b_pubs == []:
        pass
    else:
        priv_JSON["blocked_pubkeys"].append(b_pubs)

    if b_users ==[]:
        pass
    else:
        priv_JSON["blocked_usernames"].append(b_users)

    if b_words ==[]:
        pass
    else:
        priv_JSON["blocked_words"].append(b_words)
    if fav_mes_sig ==[]:
        pass
    else:
        priv_JSON["favourite_message_signatures"].append(fav_mes_sig)
    
    if b_mes_sig ==[]:
        pass
    else:
        priv_JSON["blocked_message_signatures"].append(b_mes_sig)
    
    
    #CAN use for testing private data
    # priv_JSON["friends_usernames"].clear()
    # priv_JSON["blocked_pubkeys"].clear()
    # priv_JSON["blocked_usernames"].clear()
    # priv_JSON["blocked_words"].clear()
    # priv_JSON["favourite_message_signatures"].clear()
    # priv_JSON["blocked_message_signatures"].clear()
    # priv_JSON["group_key"].clear()
    

    priv_JSON = json.dumps(priv_JSON)

    pass_byte = bytes(password, encoding='utf-8')

    message = bytes(priv_JSON,encoding= 'utf-8')

    kdf = nacl.pwhash.argon2i.kdf


    salt_size = nacl.pwhash.argon2i.SALTBYTES 


    salt = pass_byte * 16

    salt_byte = salt[:16]



    key = kdf(nacl.secret.SecretBox.KEY_SIZE, pass_byte, salt_byte,nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE)

    secret_box = nacl.secret.SecretBox(key)

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)



    p_data = secret_box.encrypt(message,nonce,encoder=nacl.encoding.Base64Encoder)




    data = p_data.decode('utf-8')


    return data

def get_privatedata(self,username, apikey):

    url = "http://cs302.kiwi.land/api/get_privatedata"

    headers = {
        #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'X-username' : username,
        'X-apikey': apikey,
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {

    }

    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data = payload,headers=headers)

        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))


    data = JSON_object['privatedata']
    return data


def privateMessage(self,login,t_pub,t_user,message,username,apiKey,signing_key,url):


    headers = {
           
        'X-username' : username,
        'X-apikey': apiKey,
        'Content-Type' : 'application/json; charset=utf-8',
    }

    e_mes = encrypt_dm(self,t_pub,message)
    tim = str(time.time())
    
    
    sig_bytes = bytes(login + t_pub + t_user + e_mes + tim, encoding='utf-8')

    signed = signing_key.sign(sig_bytes, encoder=nacl.encoding.HexEncoder)
    sig_str = signed.signature.decode('utf-8')

    payload = {
        "loginserver_record" : login,
        "target_pubkey":t_pub,
        "target_username":t_user,
        "encrypted_message":e_mes,
        "sender_created_at" : tim,
        "signature": sig_str
    }
    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req,timeout=0.01)
        data = response.read() 
        encoding = response.info().get_content_charset('utf-8') 
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    
    JSON_object = json.loads(data.decode(encoding))

    print(JSON_object)


def encrypt_dm(self,pub,message):


  
    message = bytes(message,encoding='utf-8')
    verifykey = nacl.signing.VerifyKey(pub, encoder=nacl.encoding.HexEncoder)
    publickey = verifykey.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(publickey)
    

    encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)

    e_message = encrypted.decode('utf-8')

    return e_message
 

def decrypt_dm(self,pub,e_data):

 
    publickey = pub.to_curve25519_private_key()

    sealed_box = nacl.public.SealedBox(publickey)


    e_data = e_data.encode('utf-8')

    data = sealed_box.decrypt(e_data,encoder=nacl.encoding.HexEncoder)

    data = data.decode('utf-8')

    data = BeautifulSoup(data)
    data = data.get_text()


    return data




def check_messages(self,url_in):

    url = "http://"+ url_in +"/api/checkmessages"
    
    headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        #'X-username' : username,
        #'X-apikey': apiKey,
        'Content-Type' : 'application/json; charset=utf-8',
    }
    

    payload = {
        "since":str(time.time())
    }
    payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req,timeout=2)
        data = response.read() 
        encoding = response.info().get_content_charset('utf-8') 
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    
    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    return JSON_object



def group_invite(self,login,t_pub,t_user,signing_key,apiKey,username,g_name,url):
    headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'X-username' : username,
        'X-apikey': apiKey,
        'Content-Type' : 'application/json; charset=utf-8',
    }
    buffer = encrypt_group(self,t_pub,g_name)
    g_hash = buffer[1]
    e_groupKey = buffer[0]

    tim = str(time.time())

    concat = bytes(login + g_hash + t_pub + t_user + e_groupKey + tim, encoding='utf-8')


    signed = signing_key.sign(concat, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')


    payload = {
        "loginserver_record":login,
        "groupkey_hash":g_hash,
        "target_pubkey":t_pub,
        "target_username":t_user,
        "encrypted_groupkey":e_groupKey,
        "sender_created_at":tim,
        "signature":signature_hex_str,


    }
    payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req,timeout=3)
        data = response.read() 
        encoding = response.info().get_content_charset('utf-8') 
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    
    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    return JSON_object

    

def encrypt_group(self,t_pub,name):

    g_name_bytes = bytes(name,encoding='utf-8')
    key_byte = name * 16


    key_byte = bytes(key_byte.encode('utf-8')[:16])
    key_byte = bytes(key_byte)
    key = nacl.pwhash.argon2i.kdf(nacl.secret.SecretBox.KEY_SIZE,g_name_bytes,key_byte,nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE)

    hashed = nacl.hash.sha256(key,encoder=nacl.encoding.HexEncoder)
    hashed = hashed.decode('utf-8')

    # t_pub = veri
    # curver_t_pub = t_pub.to_curve25519_public_key()
    # box = SealedBox(curver_t_pub)


    verifykey = nacl.signing.VerifyKey(t_pub, encoder=nacl.encoding.HexEncoder)
    publickey = verifykey.to_curve25519_public_key()
    sealed_box = SealedBox(publickey)


    e_groupKey = (sealed_box.encrypt(key,encoder=nacl.encoding.HexEncoder)).decode('utf-8')
    print(e_groupKey)
    return e_groupKey,hashed


def decrypt_group(self,priv,enc_key):
    verifykey = nacl.signing.VerifyKey(priv,encoder=nacl.encoding.HexEncoder)
    priKey = verifykey.to_curve25519_public_key()
    seal_box = SealedBox(priKey)
    enc_key = enc_key.encode('utf-8')

    group_key = seal_box.decrypt(enc_key,encoder=nacl.encoding.HexEncoder)

    return group_key



def group_message(loginserver_record,g_hash,mes,signing_key):

    headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'X-username' : username,
        'X-apikey': apiKey,
        'Content-Type' : 'application/json; charset=utf-8',
    }


    enc_message= en_group_mes(mes)

    tim = str(time.time())

    buffer = bytes(loginserver_record + g_hash + enc_message + tim,encoding='utf-8')


    sig = signing_key.sign(buffer,encoder=nacl.encoding.HexEncoder)

    payload = {
        "loginserver_record": loginserver_record,
        "groupkey_hash":g_hash,
        "group_message":enc_message,
        "sender_created_at":tim,
        "signature":sig

    }
    payload = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req,timeout=3)
        data = response.read() 
        encoding = response.info().get_content_charset('utf-8') 
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    
    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    return JSON_object






def en_group_mes(self,message):
    message_bytes = bytes(message,encoding='utf-8')
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(message_bytes, nonce, encoder=nacl.encoding.Base64Encoder)
    return encrypted.decode('utf-8')


def dec_group_mes(self,enc_mes,g_pass):

    b_g_pass = bytes(g_pass,encoding = 'utf-8')
    k_pass = b_g_pass * 16
    salt = bytes(k_pass.encode('utf-8')[:16])
    key = nacl.pwhash.argon2i.kdf(nacl.secret.SecretBox.KEY_SIZE,g_name_bytes,salt,nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE,nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE)
    box = nacl.secret.SecretBox(key)
    message = box.decrypt(enc_mes, encoder=nacl.encoding.Base64Encoder)
    message = message.decode('utf-8')
    return message






#def en_group_mes(self,)
# def createHash(self,name):
#     message = bytes(name,encoding='utf-8')
#     hash_name = nacl.hash.sha256(message,encoder=nacl.encoding.Hexcoder)
#     return hash_name




#def decrypt_G_mes(self,e_message):

