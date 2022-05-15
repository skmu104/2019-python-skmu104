import cherrypy
import nacl.signing
import nacl.encoding
import api
import socket
import time
import database
import json

startHTML = """<html><head><meta http-equiv="refresh" content="60"><title>CS302 Surajs WebServer</title><link rel='stylesheet' href='/static/example.css' /></head><body>"""

class MainApp(object):



    userlist = []

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self,status = "0"):
        """Main homepage"""
        Page = startHTML + """<h2><header>Howdy! Welcome to Old Road Town </header> </br>
         <img src="static/horsey.png"/>
         </h1><h3> The best social media network in the wild west</h3><br/>"""
        
        try:
            Page += "Greetings,<h3>" + cherrypy.session['username'] + "!</h3>   "
            Page += "Status:"
            if (cherrypy.session['state'] == "online"):
                Page += "<font color = 'white'> Online </font><br/>"
                api.report(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['publicKey'],"online")
            elif (cherrypy.session['state'] == "away"):
                Page += "<font color = 'white'> Away </font><br/>"
                api.report(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['publicKey'],"away")
            elif (cherrypy.session['state'] == "busy"):
                Page += "<font color = 'white'> Busy </font><br/>"
                api.report(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['publicKey'],"busy")

            print("reported")
            Page += "<font size='6'><a href= 'serv_mes' ><input type='button' value='Broadcast'></a>&nbsp"
            Page += "<a href= 'list_users'><input type='button' value='Online users'><a/>&nbsp"

            if cherrypy.session['authority']:
                Page += "<a href= 'fav_broads'><input type='button' value='favourite broadcasts'></font></a><br/>&nbsp"
                Page += " <a href= 'publicMessages'> <input type='button' value='Check public broadcasts'><a/><br/>"
                Page += " <a href= 'privateMessages'> <input type='button' value='Check private messages'><a/><br/>"
                Page += "<a href= 'friends_list'><input type='button' value= 'friends list'><a/>"
                Page += "<a href= 'write_block'><input type='button' value='block words'><a/>"



            Page += "<a href = 'Away'><input type='button' name='so_link' value=Away </a> "
            Page += "<a href = 'busy'> <input type='button' name='so_link' value=Busy </a>"

            Page += " <a href = 'online'> <input type='button' name='so_link' value=Online </a><br/>"

            Page += "<a href='unique_pass'><input type='button' name='so_link' value=Reset data></a>"
            Page += " <a href='/signout'><input type='button' value='sign out'></a></br>"


            self.ping_clients()

        except KeyError: 
            
            Page += "Click here to <a href='login' stlye='color:white'><input type='button' name='so_link' value='Login'</a>"
        return Page


    @cherrypy.expose
    def friends_list(self):
        """Used to display friends list"""
        Page = startHTML
        Page += "<div style='height:800px;width:500px;border:0px solid #ccc;font:16px/26px Georgia, Garamond, Serif;overflow:auto;'>"
        for i in range(len(cherrypy.session['priv_data']['friends_usernames'])):
            Page += "<h1>" + cherrypy.session['priv_data']['friends_usernames'][i]+ "</br>"
        
        Page += "</h1></div>"
        Page += "<font color = 'red'> Click here to <a href='index'> <input type='button' value='Go back'>"
        return Page

    @cherrypy.expose
    def write_block(self):
        """Used to input word to be blocked"""
        Page = startHTML
        Page += '<form action="/add_block" method="post" enctype="multipart/form-data">'
        Page += 'message: <input type="text" name="message"/></br>'
        Page += '<input type="submit" value="send"/></form>'
        return Page


    @cherrypy.expose
    def add_block(self,message):
        """Blocks another user"""
        api.add_privatedata(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['U_pass'],cherrypy.session['login_record'],cherrypy.session['signing_key'],cherrypy.session['priv_data'],cherrypy.session['privateKey'].decode("utf-8"),[],[],message,[],[],[])
        raise cherrypy.HTTPRedirect('/')




    @cherrypy.expose
    def fav_broads(self):
        """Used to display favourited broadcasts"""
        Page = startHTML
        Page += "Locally favorited broadcasts<div style='height:800px;width:500px;border:0px solid #ccc;font:16px/26px Georgia, Garamond, Serif;overflow:auto;'>"
        try:
            b = database.favBroads(self,cherrypy.session['priv_data']['favourite_message_signatures'])

            for i in b:
               
                Page += "<body><font color = 'black'>"+i[0]+"</font>&nbsp:"+i[1]+"&nbsp:<font color = 'red'>"+i[2]+"</font>"
                Page += "</br>"
        except:
            pass
        Page += "</div></body><font color = 'red'> Click here to <a href='index'> <input type='button' value='Go back'>"
        return Page


    def ping_clients(self):
        """Used to iterate through other user locations and check status of their client"""
        cherrypy.session['user_list']= api.list_users(self,cherrypy.session['username'],cherrypy.session['api_key'])
        
        for i in range(len(cherrypy.session['user_list']['users'])):
            
            try:

                api.ping_check(self,"http://"+cherrypy.session['user_list']['users'][i]['connection_address']+"/api/ping_check")

            except:
                pass
        
        
    @cherrypy.expose
    def publicMessages(self):
        """Used to display public messages sent to user"""
        Page = startHTML
        Page += "Following are the public messages"
        Page += """<list><div style="height:800px;width:500px;border:0px solid #ccc;font:16px/26px Georgia, Garamond, Serif;overflow:auto;">"""

        pubs = database.loadPubs(self)

        for i in range(len(pubs['message'])):
 
        
            for j in range(len(cherrypy.session['priv_data']['blocked_usernames'])):
                if (cherrypy.session['priv_data']['blocked_usernames'][j] == pubs['user'][len(pubs['message'])-i-1]):
                    pass
                    #print("suceess")
                else:
                    block = False
 
                    for z in cherrypy.session['priv_data']['blocked_words']:

                        if z not in pubs['message'][len(pubs['message'])-i-1]:

                            pass
                        else:
                            block = True

                    if block == False:
                        Page += "<font color= 'black'>"+ pubs['user'][len(pubs['message'])-i-1] +"</font>:" + pubs['message'][len(pubs['message'])-i-1] +"<font color='red'> </font> <a href=fav_b?time=" +pubs['time'][len(pubs['message'])-i-1]+">favourite</a></br>" 
                    else:
                        pass

            if len(cherrypy.session['priv_data']['blocked_usernames']) == 0:
                block = False

                for z in cherrypy.session['priv_data']['blocked_words']:

                    if z not in pubs['message'][len(pubs['message'])-i-1]:

                        pass
                    else:
                        block = True

                if block == False:
                    Page += "<font color= 'black'>"+ pubs['user'][len(pubs['message'])-i-1] +"</font>:" + pubs['message'][len(pubs['message'])-i-1] +"<font color='red'> + </font> <a href=fav_b?time=" +pubs['time'][len(pubs['message'])-i-1]+">favourite</a></br>" 
                else:
                    pass

        Page += "</list></div>"
        Page += "<font color = 'red'> Click here to <a href='index'> <input type='button' value='Go back'>"
        return Page
    

    @cherrypy.expose
    def fav_b(self,time):
        """Used to add favourite broadcasts signature to private data"""
        mes_sig = database.selectBroad(self,time)
        api.add_privatedata(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['U_pass'],cherrypy.session['login_record'],cherrypy.session['signing_key'],cherrypy.session['priv_data'],cherrypy.session['privateKey'].decode("utf-8"),[],[],[],[],mes_sig[0],[])
        raise cherrypy.HTTPRedirect("/publicMessages")
        Page = startHTML
        Page += ""+ time + ""
        return Page

    @cherrypy.expose
    def privateMessages(self):
        """Used to open private messages that are intended for user"""
        Page = startHTML
        Page += "Following are your private messages"
        privs = database.loadPriv(self)

        Page += """<div style="height:800px;width:500px;border:0px solid #ccc;font:16px/26px Georgia, Garamond, Serif;overflow:auto;">"""
        for i in range(len(privs['e_message'])):
            try:
                block = False
                    
                mes = api.decrypt_dm(self,cherrypy.session['signing_key'],privs['e_message'][len(privs['e_message'])-i-1])
                for z in cherrypy.session['priv_data']['blocked_words']:
                    if z not in mes:
                        pass
                    else:
                        block = True
                        break
                

                if block == False: 
                    Page += ""+privs['user'][len(privs['e_message'])-i-1] + " : " + mes+"</br>"
                else:
                    pass

            except:
                pass
        Page += "</div>"
        Page += "<font color = 'red'> Click here to <a href='index'> go back"
        return Page


    @cherrypy.expose
    def Away(self):
        """Used to set status of user to away"""
        api.report(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['publicKey'],"away")
        cherrypy.session['state'] = "away"
        raise cherrypy.HTTPRedirect('/?status=1')
    
    @cherrypy.expose
    def busy(self):
        """Used to set status of user to busy"""
        api.report(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['publicKey'],"busy")
        cherrypy.session['state'] = "busy"
        raise cherrypy.HTTPRedirect('/?status=2')   

    @cherrypy.expose
    def online(self):
        """used to set status of user to Online"""
        api.report(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['publicKey'],"online")
        cherrypy.session['state'] = "online"
        raise cherrypy.HTTPRedirect('/?status=0')     
        
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML 
        Page += "<h2><header><b>You've been here before partner?</b></h2></header></br>"
        if bad_attempt != 0:
            Page += "<font color='red'><body>Invalid username/password!</font>"
            
        Page += '<font size = 10><user_input><form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/></br></br>'
        Page += 'Password: <input type="password" name="password"/></user_input></br></br>'
        #test using hyperlink
        Page += '<input type="submit" value="Login"/></form></body>'
        return Page
    
    def write_dm(self,user):
        """Form to write private message"""
        Page = startHTML
        Page += '<form action="/dm" method="post" enctype="multipart/form-data">'
        Page += 'message: <input type="text" name="message"/></br>'
        Page += '<input type="submit" value="send"/></form>'

    @cherrypy.expose
    def check_mes(self):
        read = False
        cherrypy.session['user_list']= api.list_users(self,cherrypy.session['username'],cherrypy.session['api_key'])
        for i in range(len(cherrypy.session['user_list']['users'])):
            try:
                resp = api.check_messages(self,cherrypy.session['user_list']['users'][i]['connection_address'])
                read = True
            except:
                pass
        
        if read == True:
            if (len(resp['broadcasts']) > 0):
                for i in range(len(resp['broadcasts'])):
                    try:
                        storePubmes(resp['broadcasts'][i]['loginserver_record'],resp['broadcasts'][i]['message'],resp['broadcasts'][i]['sender_created_at'],resp['broadcasts'][i]['signature'])
                    except:
                        pass
        
        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def dm(self,user="skmu104",message=None):
        """Not currently used but a testing feature used previously"""
        online = False
        cherrypy.session['user_list']= api.list_users(self,cherrypy.session['username'],cherrypy.session['api_key'])

        for i in range(len(cherrypy.session['user_list']['users'])): 
            if (cherrypy.session['user_list']['users'][i]['username'] == cherrypy.session['tx']):
                online = True
                try:

                    api.privateMessage(self,cherrypy.session['login_record']['loginserver_record'],cherrypy.session['tx_pub'],cherrypy.session['tx'],message,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['signing_key'],"http://"+ cherrypy.session['tx_address']+"/api/rx_privatemessage")
                    cherrypy.session['sent']['tx'].append(user)
                    cherrypy.session['sent']['message'].append(message)
                    cherrypy.session['sent']['time'].append(str(time.time()))
                 
                except:
                    pass

                cherrypy.session['sent']['tx'].append(user)
                cherrypy.session['sent']['message'].append(message)
                cherrypy.session['sent']['time'].append(str(time.time()))
        if (online == False):
            for i in range(len(cherrypy.session['user_list']['users'])): 
                try:
                    api.privateMessage(self,cherrypy.session['login_record']['loginserver_record'],cherrypy.session['tx_pub'],cherrypy.session['tx'],message,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['signing_key'],"http://"+ cherrypy.session['tx_address']+"/api/rx_privatemessage")
                except:
                    pass
        raise cherrypy.HTTPRedirect("/user_profile?user=" + cherrypy.session['tx'] +"&tx_pub="+cherrypy.session['tx_pub']+"&tx_address="+cherrypy.session['tx_address'])


    @cherrypy.expose
    def user_profile(self,user,tx_pub,tx_address):
        """webpage display for providing options for user to user interaction"""
        Page = startHTML
        cherrypy.session['tx'] = user
        cherrypy.session['tx_pub'] = tx_pub
        cherrypy.session['tx_address'] = tx_address
        
        blocked = False
        Page += "<h2><center>" + user + "</h2></br>"
        Page += "Recevied</br>"
        Page += """<list><div style="height:200px;width:700px;border:0px solid #ccc;font:20px/46px Georgia, Garamond, Serif;overflow:auto;">"""
        privs = database.showPriv(self,cherrypy.session['username'],cherrypy.session['tx'])



        
 

        for j in range(len(cherrypy.session['priv_data']['blocked_usernames'])):
            blocked = False
            if (cherrypy.session['priv_data']['blocked_usernames'][j] != user):
                pass
                
            else:
                blocked = True
                break
        

        if blocked == False:
            for i in range(len(privs['e_message'])):
                try:

                    t = int(float(privs['time'][len(privs['e_message'])-i-1]))

                    mes = api.decrypt_dm(self,cherrypy.session['signing_key'],privs['e_message'][len(privs['e_message'])-i-1])
                   
                    stop = False
                    for z in cherrypy.session['priv_data']['blocked_words']:
                        if z not in mes:
                            pass
                        else:
                            stop = True
                    if stop == False:
                        Page += ""+privs['user'][len(privs['e_message'])-i-1] + " : " + mes+"&nbsp&nbsp&nbsp<font color='red'>"+time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t)) +"</font></br>"
                    else:
                        pass


                except:
                    pass

        Page += "</div>"
        Page += "Sent</br>"
        Page += """<list><div style="height:200px;width:700px;border:0px solid #ccc;font:20px/46px Georgia, Garamond, Serif;overflow:auto;">"""
        for i in range (len(cherrypy.session['sent']['time'])):
            try:
                t = int(float(cherrypy.session['sent']['time'][len(cherrypy.session['sent']['time'])-i -1 ]))
                Page += ""+cherrypy.session['username'] + " : " + cherrypy.session['sent']['message'][len(cherrypy.session['sent']['time'])-i -1] + "&nbsp&nbsp&nbsp<font color='red'>"+time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t)) +"</font></br>"
            except:
                pass

        Page += "</div><a href=add_friend?user="+user+"><buton>Add to Friends list</button></a href></br>"
        Page += "<a href=block_user?user="+user+"><buton>Block user</button></a href></br>"
        Page += "<a href=group_name?user="+user+"><buton>Invite into group</button></a href></br>"
        Page += '<form action="/dm" method="post" enctype="multipart/form-data">'
        Page += 'message: <input type="text" name="message"/></br>'
        Page += '<input type="submit" value="send"/></form>'
        Page += "<font color = 'red'><center> Click here to <a href='index'> go back</center>" 
        return Page


    @cherrypy.expose
    def group_name(self,user):
        """function used to invite group members"""
        Page = startHTML
        Page += '<form action="/group_invite" method="post" enctype="multipart/form-data">'
        Page += 'name: <input type="text" name="name"/></br>'
        Page += '<input type="submit" value="send"/></form>'
        return Page


    @cherrypy.expose
    def group_invite(self,name):
        """partially completed, havnt tested but this would be the function for group inviting"""
        api.group_invite(self,cherrypy.session['login_record']['loginserver_record'],cherrypy.session['tx_pub'],cherrypy.session['tx'],cherrypy.session['signing_key'],cherrypy.session['api_key'],cherrypy.session['username'],name,"http://"+ cherrypy.session['tx_address']+"/api/groupinvite")
        raise cherrypy.HTTPRedirect('/')



    @cherrypy.expose
    def add_friend(self,user):
        """Adds selected user to current users friend list stored in their private data"""
        api.add_privatedata(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['U_pass'],cherrypy.session['login_record'],cherrypy.session['signing_key'],cherrypy.session['priv_data'],cherrypy.session['privateKey'].decode("utf-8"),[],[],[],[],[],user)
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def block_user(self,user):
        """Used to block another user"""
        api.add_privatedata(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['U_pass'],cherrypy.session['login_record'],cherrypy.session['signing_key'],cherrypy.session['priv_data'],cherrypy.session['privateKey'].decode("utf-8"),cherrypy.session['tx_pub'],user,[],[],[],[])
        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def clientPing(self):
        """responsible to client pings"""
        api.ping_check(self)
        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def unique_pass(self):
        """function used to reset password"""
        Page = startHTML
        Page += '<form action="/add_p_data" method="post" enctype="multipart/form-data">'
        Page += 'unique password: <input type="text" name="unique_password"/></br>'
        Page += '<input type="submit" value="send"/></form>'
        return Page


    @cherrypy.expose
    def re_enter_pass(self):
        
        Page = startHTML
        Page += '<form action="/load_data" method="post" enctype="multipart/form-data">'
        Page += 'unique password: <input type="text" name="unique_password"/></br>'
        Page += '<input type="submit" value="send"/></form>'
        return Page

    





    
    @cherrypy.expose
    def initial_assign(self,unique_password=None):
        """If unique password is correct, obtains and decrypts the users private data"""
        Page = startHTML

        priv_data = api.get_privatedata(self,cherrypy.session['username'],cherrypy.session['api_key'])
        try:
            JSON_p =  api.decrypt_message(self,priv_data,unique_password)
        
            cherrypy.session['U_pass'] = unique_password
        
            cherrypy.session['priv_data'] = JSON_p

            api.add_privatedata(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['U_pass'],cherrypy.session['login_record'],cherrypy.session['signing_key'],cherrypy.session['priv_data'],cherrypy.session['privateKey'].decode("utf-8"))
      
            cherrypy.session['sent'] = {
                "tx":[],
                "message":[],
                "time":[],
            }
            cherrypy.session['authority'] = True

        except:
            Page += "<font color = 'black'> wrong password >:) </font><br/>"
            print("incorrect password")

        
        raise cherrypy.HTTPRedirect('/index')
        
    



    @cherrypy.expose
    def list_users(self):
        """List users currently online / reported recently"""

        cherrypy.session['user_list']= api.list_users(self,cherrypy.session['username'],cherrypy.session['api_key'])

        Page = startHTML
        Page += """<list><div style="height:400px;width:200px;border:0px solid #ccc;font:20px/46px Georgia, Garamond, Serif;overflow:auto;">"""
                 
        for i in range(len(cherrypy.session['user_list']['users'])):
            Page+= "<font color= 'blue'><a href ='user_profile?user=" + cherrypy.session['user_list']['users'][i]['username'] +"&tx_pub="+cherrypy.session['user_list']['users'][i]['incoming_pubkey']+"&tx_address="+cherrypy.session['user_list']['users'][i]['connection_address']+"'><input type='button' value='"  + cherrypy.session['user_list']['users'][i]['username'] + "'></font></a href></br>"

            try:
                database.insert(self,cherrypy.session['user_list']['users'][i]['username'],cherrypy.session['user_list']['users'][i]['incoming_pubkey'])

                

            except:
                pass

        Page += "</list></div>"
        Page += "<body><font color = 'red'> Click here to <a href='index'> go back</body><br/>"
        return Page
   


    @cherrypy.expose
    def broadcast(self,message):
        """Takes in users message and iterates through all connection address reported recently and broadcasts"""
        cherrypy.session['user_list']= api.list_users(self,cherrypy.session['username'],cherrypy.session['api_key'])
        for i in range(len(cherrypy.session['user_list']['users'])): 
            try:
                api.rx_broadcast(self,cherrypy.session['login_record'],cherrypy.session['signing_key'],cherrypy.session['publicKey'],message,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['user_list']['users'][i]['connection_address'])
                print("success")
            except:
                pass
        Page = startHTML
        Page += "<font color = 'black'> you just broadcasted to the server </font></br>"
        Page += "<font color = 'red'> Click here to <a href='index'> go back"
        return Page




    @cherrypy.expose
    def serv_mes(self):
        """page used to confirm to user that they broadcasted"""
        Page = startHTML
        Page += '<form action="/broadcast" method="post" enctype="multipart/form-data">'
        Page += 'message: <input type="text" name="message"/></br>'
        Page += '<input type="submit" value="send"/></form>'

        return Page

    @cherrypy.expose
    def add_p_data(self,unique_password):
        JSON = {
            "prikeys":[],
            "blocked_pubkeys":[],
            "blocked_usernames":[],
            "blocked_words":[],
            "blocked_message_signatures":[],
            "favourite_message_signatures":[],
            "friends_usernames":[],
            "group_key":[]

        }
        api.add_privatedata(self,cherrypy.session['username'],cherrypy.session['api_key'],unique_password,cherrypy.session['login_record'],cherrypy.session['signing_key'],JSON,cherrypy.session['privateKey'].decode('utf-8'))
        Page = startHTML
        Page += "<font color = 'red'> Click here to <a href='index'> go back"
        return Page

    @cherrypy.expose
    def dec_p_data(self):
        Page = startHTML
        Page += "<font color = 'red'> Click here to <a href='index'> go back"
        return Page


    
    @cherrypy.expose    
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a+5)+int(b+6)
        return str(output)
        
    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(self,username, password)
        if error == 0:



            cherrypy.session['l_pub'] =  api.loginserver_pubkey(self)

            #global signature 

            infoBuffer= api.add_pubkey(self,cherrypy.session['username'],cherrypy.session['api_key'])
            cherrypy.session['publicKey'] = infoBuffer[0]
            #signature = infoBuffer[1]
            cherrypy.session['privateKey'] = infoBuffer[2]
            cherrypy.session['signing_key'] = infoBuffer[3]

            api.ping(self,cherrypy.session['publicKey'],cherrypy.session['signing_key'],cherrypy.session['username'],cherrypy.session['api_key'])

            api.report(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['publicKey'],"online")
            cherrypy.session['state'] = "online"

            cherrypy.session['authority'] = False

            cherrypy.session['login_record'] = api.loginserver_record(self,cherrypy.session['username'],cherrypy.session['api_key'])

            try:
                database.insert(self,cherrypy.session['username'],cherrypy.session['publicKey'])

            except:
                pass

            database.read(self)

            raise cherrypy.HTTPRedirect('/load_personal')

        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
    @cherrypy.expose
    def no_auth(self):
        cherrypy.session['authority'] = False
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def load_personal(self):
            Page = startHTML
            Page += "<header>Load personal info</header>"
            Page += '<body><user_input><form action="/initial_assign" method="post" enctype="multipart/form-data">'
            Page += 'unique password: <input type="password" name="unique_password"/></br>'
            Page += '<b><input type="submit" value="load"></form>'
            Page += "<a href='no_auth'><input type='button' value='Guest'></b></a></user_input></body>"
 
            return Page





    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            api.report(self,cherrypy.session['username'],cherrypy.session['api_key'],cherrypy.session['publicKey'],"offline")
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')
    
    def add_private(self):
        Page = startHTML
        Page += '<form action="/index" method="post" enctype="multipart/form-data">'
        Page += 'password: <input type="text" name="message"/></br>'
        Page += '<input type="submit" value="send"/></form>'





class ApiApp(object):
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 } 
    



    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

        

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        
        message = cherrypy.request.json["message"]

        login = cherrypy.request.json["loginserver_record"]
        time = cherrypy.request.json["sender_created_at"]

        sig = cherrypy.request.json["signature"]

        storePubmes(self,login,message,time,sig)
        
   
        response = """{"response":"ok"}"""
 
        return response


    @cherrypy.expose    
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_groupmessage(self):
        print(cherrypy.request.json['group_message'])
        response = {
            "response" : "ok"
        }
        response = json.dumps(response)

        return response



    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        print("idk")
        print(cherrypy.request.json["target_username"])
        print(cherrypy.request.json["target_pubkey"])
        login = cherrypy.request.json["loginserver_record"]
        time = cherrypy.request.json["sender_created_at"]
        e_message = cherrypy.request.json["encrypted_message"]

        sender = login.split(",")[0]
        pub = login.split(",")[1]
        sig = login.split(",")[3]
        target_user = cherrypy.request.json["target_username"]
        target_pub = cherrypy.request.json["target_pubkey"]

        database.savePriv(self,sender,pub,e_message,time,sig,target_user,target_pub)

        response = """{"response":"ok"}"""
        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):
        t = str(time.time())
        print(cherrypy.request.json['connection_address'])
        response = """{
            "response":"ok",
            "my_time": """+ t + """,

        }"""

        return response



    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_groupinvite(self):


        try:
            login = cherrypy.request['loginserver_record']
            t_pub = cherrypy.request['target_pubkey']
            t_user =cherrypy.request['target_username']
            t_hash = cherrypy.request['groupkey_hash']
            enc_key = cherrypy.request['encrypted_groupkey']
            tim = cherrypy.request['sender_created_at']
            sig = cherrypy.request['signature']
            database.insert_group_key(self,t_user,t_pub,t_hash,enc_key,tim,sig)
            response = {
                "response" : "ok"
            }
        except:
            response = {
                "response" : "error"
            }
            pass

        response = json.dumps(response)
        return response



    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def checkmessages(self,since=None):
        response = {
            "response" : "ok"
        }

        response = json.dumps(response)
        return response

    @cherrypy.expose
    def start(self):
        Page = startHTML + "hmm good starting point"
        Page += cherrypy.session.get('username')
        print(cherrypy.session.get('username'))
        return Page



def setUsername(self,username):
    cherrypy.session['username'] = username
    
def storePubmes(self,user,message,t,sig):

    sender = user.split(",")[0]
    pub = user.split(",")[1]
    database.savePub(self,sender,pub,message,t,sig)

    



def authoriseUserLogin(self,username, password):
    print("Log on attempt from {0}:{1}".format(username, password))
 
    try:
        login_buff = api.load_new_apikey(self,username,password)
    except:
        return 1

    if (login_buff[1] == "ok"):
        cherrypy.session['api_key']= login_buff[0]
        cherrypy.session['username'] = username
        print("Successful login")
        return 0
    else: 
        return 1



