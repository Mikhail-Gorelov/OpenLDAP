#!/usr/bin/env python3.6
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3 import MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE
import sys
import argparse
import os
from ldap3.core.exceptions import LDAPCursorError
from ldap3 import  NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS
import configparser
import os
import logging
import json
import hashlib
import os
import base64

logging.basicConfig(level=logging.INFO)
path = "attributes.ini"
config = configparser.ConfigParser()
config.read(path)

def make_secret(password):
    """
    Encodes the given password as a base64 SSHA hash+salt buffer
    """
    # hash the password and append the salt
    enc = base64.b64encode(password.encode('utf-8'))
    return enc.decode()

def decode_secret(code):
    # the entire payload is base64-encoded
    dec = base64.b64decode(code)
    return dec.decode()

def my_input():
    print("Enter new admin password:")
    passwd = str(input())
    config.set("Settings", "password",  make_secret(passwd))
    with open(path, "w") as config_file:
        config.write(config_file)

if config.get("Settings", "password") == "None":
    my_input()

domain = config.get("Settings", "domain")
host = config.get("Settings", "host")
ou = config.get("DC", "ou")
person_attr = config.get("BasicAttributes", "person_attr") 
group_attr = config.get("BasicAttributes", "group_attr")
minuidnumber = int(config.get("User", "minuidnumber"))
mingidnumber = int(config.get("Group", "mingidnumber"))
list_all_persons = '(objectclass=person)'
list_all_groups = '(objectclass=posixGroup)'

server_uri = host
server = Server(server_uri, get_info=ALL)

def connect_to_ldap(server, password):
    connection = Connection(server,
                                    user=f"cn=admin,{domain}",
                                    password=password)
    return connection

password_conf = config.get("Settings", "password")
bind_con  = connect_to_ldap(server, decode_secret(password_conf)).bind()
while bind_con != True:
    logging.warning("The password is bad. Reenter password:")
    my_input()
    password_conf = config.get("Settings", "password")
    bind_con = connect_to_ldap(server, decode_secret(password_conf)).bind()

connection = connect_to_ldap(server, decode_secret(password_conf))
connection.bind()
connection2 = connect_to_ldap(server, decode_secret(password_conf))
connection2.bind()

parser = argparse.ArgumentParser()

parser.add_argument("--cmd", choices=['add', 'del', 'list', 'change'], required=True)
parser.add_argument("--name")
parser.add_argument("--type", choices=['user', 'group'], required=True)
parser.add_argument("--password")
parser.add_argument("--memberuid")
parser.add_argument("--gidnumber")

args = parser.parse_args()

cmd=args.cmd 
name=args.name
type=args.type
password = args.password
memberuid = args.memberuid
gidnumber = args.gidnumber


user_obj_class = config.get('UserobjClass' , 'objectClass').split()
group_obj_class = config.get('GroupobjClass' , 'objectClass').split()
dc_obj_class = config.get('DCobjClass' , 'objectClass').split()

user_attributes = dict(config.items("User"))
group_attributes = dict(config.items("Group"))
dc_attributes = dict(config.items("DC"))

def create_user(user, group, password, minuid):
    connection.search(f"{domain}",search_filter=f"{list_all_persons}", attributes='uidNumber')
    arr = []
    for i in connection.entries:
        arr.append(i.uidNumber.value) 
    for uid in range(minuid,minuid*minuid,1):
        if str(uid) in arr:
            continue
        else:
            minuid = uid
            break

    connection.search(f"{domain}", search_filter=f"(&(cn={group})(objectClass=posixGroup))",attributes='gidNumber')
    gid_num = int(connection.entries[-1].gidNumber.value) #making unique gidNumbe
    
    connection.add(dn=f"cn={user},dc={group},{domain}", object_class=user_obj_class, attributes={'sn':user, 'uid':user, 'homeDirectory':f"/home/{group}/{user}", 'uidNumber':minuid, 'gidNumber':gid_num, 'loginShell':'/bin/bash','userPassword':password })

def create_group(group, mingid):
    connection.search(f"{domain}", search_filter=f"{list_all_groups}",attributes='gidNumber')
    arr = []
    for i in connection.entries:
        arr.append(i.gidNumber.value)
    for gid in range(mingid,mingid*mingid,1):
        if str(gid) in arr:
            continue
        else:
            mingid = gid
            break

    connection.add(dn=f"cn={name},ou={ou},{domain}", object_class=group_obj_class, attributes={'gidNumber': mingid})
    connection.add(dn=f"dc={name},{domain}", object_class=dc_obj_class, attributes=dc_attributes)

def modify_memberuid(func, user, group, guidnumber=None):

    connection.search(f"{domain}", search_filter=f"(&(cn={group})(objectClass=posixGroup))")

    if not connection.entries: #check existing group in DB
        logging.error("There is no group here!")
        return
        
    if func == 'add':
        connection.modify(f"cn={group},ou={ou},{domain}",{'memberUid': [(MODIFY_ADD, [user])]})
    if func == 'del':
        connection.modify(f"cn={group},ou={ou},{domain}",{'memberUid': [(MODIFY_DELETE, [user])]})
    if func == 'change':
        old_user = user.split(":")[0]
        new_user = user.split(":")[1]
        connection.modify(f"cn={group},ou={ou},{domain}",{'memberUid': [(MODIFY_DELETE, [old_user])]})
        connection.modify(f"cn={group},ou={ou},{domain}",{'memberUid': [(MODIFY_ADD, [new_user])]})

def modify_gidnumber(name, guidnumber):
    user = name.split(":")[0]
    group = name.split(":")[1]

    connection.search(f"{domain}", search_filter=f"(&(cn={user})(objectClass=person))")    

    if not connection.entries: #check existing group in DB
        logging.error("There is no user here!")
        return

    connection.modify(f"cn={user},dc={group},{domain}",{'gidNumber': [(MODIFY_REPLACE, [guidnumber])]})

#adding user and group
if cmd == 'add':
    if type == 'user':
        user = name.split(":")[0]
        group = name.split(":")[1]
    
        connection.search(f"{domain}", search_filter=f"(&(cn={user})(objectClass=person))")

        if not connection.entries: #check existing user in DB
            create_user(user, group, password, minuidnumber)
            modify_memberuid(cmd, user, group)
            logging.info("OK")

        else:
            logging.error("ERROR! The user already exists!")

    elif type == 'group':
        connection.search(f"{domain}", search_filter=f"(&(cn={name})(objectClass=posixGroup))")

        if not connection.entries: #check existing group in DB

            create_group(name, mingidnumber)
            logging.info("OK")

        else:
            logging.error("The group already exists!")

#deleting user and group
#there is no use in config now
elif cmd == 'del':

    if type == 'user':
        user = name.split(":")[0]
        group = name.split(":")[1]

        connection.search(f"{domain}", search_filter=f"(&(cn={user})(objectClass=person))")

        if not connection.entries: #check existing user in DB
            logging.error("There is no user to delete!")

        connection.search(f"{domain}", search_filter=f"(&(cn={group})(objectClass=posixGroup))")

        if not connection.entries: #check existing group in DB
            logging.error("There is no group where I can find user!")
        
        modify_memberuid(cmd, user, group)
        connection.delete(f"cn={user},dc={group},{domain}")
        logging.info("OK")

    elif type == 'group':

        connection.search(f"{domain}", search_filter=f"(&(cn={group})(objectClass=posixGroup))")

        if not connection.entries: #check existing group in DB
            logging.error("There is no group to delete!")

        connection.delete(f"cn={name},{ou},{domain}")
        logging.info("OK")

#changing user and group names
#there is no use in config now
elif cmd == 'change':

    if type == 'user':
        #modify gidNumber
        if gidnumber != None:
            #modify_memberuid('del', name.split(":")[0], name.split(":")[1])
            modify_gidnumber(name, gidnumber)
        else:
            old_user = name.split(":")[0]
            group = name.split(":")[1]
            new_user = name.split(":")[2]
        
            connection.search(f"{domain}", search_filter=f"(&(cn={old_user})(objectClass=person))")

            if not connection.entries: #check existing user in DB error
                logging.error("There is no user to rename!")

            connection.search(f"{domain}", search_filter=f"(&(cn={group})(objectClass=posixGroup))")

            if not connection.entries: #check existing group in DB
                logging.error("There is no group where I can find user!")

            connection.modify_dn(f"cn={old_user},dc={group},{domain}", f"cn={new_user}")
            modify_memberuid(cmd, f"{old_user}:{new_user}", group)       
            logging.info("OK")


    elif type == 'group':

        old_group = name.split(":")[0]
        new_group = name.split(":")[1]      

        connection.search(f"{domain}", search_filter=f"(&(cn={old_group})(objectClass=posixGroup))")

        if not connection.entries: #check existing group in DB
            logging.error("There is no group to rename!")

        connection.modify_dn(f"cn={old_group},ou={ou},{domain}", f"cn={new_group}")
        logging.info("OK")


#listing all users and groups
#there is no use in config now
elif cmd == 'list':

    if type == 'user':
        connection.search(f"{domain}", f"{list_all_persons}", attributes={'cn','gidNumber','uidNumber'})
        json_people_test = {}
        for r in range(0,len(connection.entries)):
            connection2.search(f"{domain}", f"(&(gidNumber={connection.entries[r].gidNumber})(objectClass=posixGroup))", attributes={'cn'})
            if not connection2.entries:
                json_people_test[connection.entries[r].cn.value] = connection.entries[r].entry_to_json()
            else:
                string = '{"Department" : "' + connection2.entries[-1].cn.value + '"}'
                test = json.loads(string)
                json_people_test[connection.entries[r].cn.value] = connection.entries[r].entry_to_json(), test
        for key in json_people_test:
            print(f"{key}")
            print (json.dumps(json_people_test[key],indent=4, sort_keys=True, separators=(',', ': ')).replace('\\n','\n').replace('\\', ''))
            print("-----------------------------")
    elif type == 'group':
        connection.search(f"{domain}", f"{list_all_groups}", attributes={'cn','gidNumber','memberUid'})
        json_group_test = {}
        for r in range(0,len(connection.entries)):
            json_group_test[connection.entries[r].cn.value] = connection.entries[r].entry_to_json()
        for key in json_group_test:
            print(key)
            print(json_group_test[key])
            print("----------------------------")

    else:
        logging.error("Wrong key!")

