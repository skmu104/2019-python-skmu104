import sqlite3
import xml.etree.ElementTree
from bs4 import BeautifulSoup



# conn = sqlite3.connect("data.db")
# c = conn.cursor()
# # # #code used to create table
# # # c.execute("create table users(id integer primary key autoincrement not null, username text not null, publicKey text not null,UNIQUE(id,username))")
#c.execute("create table group_key(t_user text not null, t_pub text not null ,t_hash text not null,enc_key text,sender_created_at text unique,signature text not null)")
# drop = "DROP TABLE fav_broad"
# c.execute(drop)
# # # c.execute("insert into users (username) values (skmu104)")
#c.execute("create table private_messages(s_user text not null, s_pub text not null,e_message text,sender_created_at text,s_sig text not null,t_user text not null,t_pub text not null)")
# conn.commit()
# conn.close()


#conn.commit()


#conn.close()

#conn = sqlite3.connect("data.db")
#c = conn.cursor()


#c.execute("create table fav_broad(sender text not null,broadcasts text not null,time text not null ,unique(time))")
#c.execute("DROP TABLE fav_broad")
#conn.commit()
#conn.close()



def insert(self,user,pub):
    passing = (user,pub)

    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("insert into users (username,publicKey) values(?,?)",passing)
    conn.commit()
    conn.close()



def read(self):
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("SELECT username,publicKey from users")
    info = c.fetchall()
 
    conn.close()


def savePub(self,user,pub,mes,time,sig):
    mes = BeautifulSoup(mes)
    mes = mes.get_text()
    
    passing = (user,pub,mes,time,sig)
  
    conn =sqlite3.connect("data.db")
    c =conn.cursor()
    c.execute("insert into public_messages (username,publicKey,message,sender_created_at,signature) values (?,?,?,?,?)",passing)
    conn.commit()
    conn.close()


def loadPubs(self):
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("SELECT username,message,sender_created_at from public_messages")
    pubs ={
        "user":[],
        "message":[],
        "time":[]
    }
   
    for row in c:
        pubs['user'].append(row[0])
        pubs['message'].append(row[1])
        pubs['time'].append(row[2])
    
    conn.close
    return pubs

def loadPriv(self):
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("SELECT s_user,e_message,sender_created_at from private_messages")
    privs ={
        "user":[],
        "e_message":[],
        "time":[]
    }
    for row in c:
        privs['user'].append(row[0])
        privs['e_message'].append(row[1])
        privs['time'].append(row[2])
    conn.close
    return privs



def savePriv(self,s_user,s_pub,e_mes,time,sig,t_user,t_pub):
    passing = (s_user,s_pub,e_mes,time,sig,t_user,t_pub)
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("insert into private_messages (s_user,s_pub,e_message,sender_created_at,s_sig,t_user,t_pub) values (?,?,?,?,?,?,?)",passing)
    conn.commit()
    conn.close()

def showPriv(self,owner,sender):
    passing= (sender,owner,owner,sender)
    conn =sqlite3.connect("data.db")
    c = conn.cursor()
    privs = {
        "user":[],
        "e_message":[],
        "time":[]
    }

    
    c.execute("SELECT s_user,e_message,sender_created_at FROM private_messages WHERE (s_user = ? AND t_user = ?) OR (s_user = ? AND t_user = ?)",passing)


    for row in c:
        privs['user'].append(row[0])
        privs['e_message'].append(row[1])
        privs['time'].append(row[2])
        print(row)
    conn.close
    return privs
 
def insert_group_key(self,t_user,t_pub,t_hash,e_key,time,sig):
    passing = (t_user,t_pub,t_hash,e_key,time,sig)
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("insert into group_key (t_user,t_pub,t_hash,enc_key,sender_created_at,signature) values (?,?,?,?,?,?)",passing)
    conn.commit()
    conn.close()

def selectBroad(self,time):

    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("SELECT signature from public_messages WHERE (sender_created_at = ?) ",[time])
  
    for row in c:
        return(row)



def favBroads(self,mes_sig):
    conn = sqlite3.connect("data.db")
    c = conn.cursor()

    for i in range(len(mes_sig)):
       
        c.execute("SELECT username,message,sender_created_at from public_messages WHERE (signature = ?)",[mes_sig[i]])
  
    
    return c



def setBroadcasts(self,b,user,time):
    b = BeautifulSoup(b)
    b = b.get_text()
    passing(sender,b,time)
    conn.sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("insert into fav_broad (sender,broadcasts) values (?)",passing)
    conn.commit()
    conn.close()
