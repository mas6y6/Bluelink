from cryptography import fernet
import websockets, sys, os, cryptography, json, pyinputplus
import getpass

from websockets.sync.client import connect

class Encrypter:
    def __init__(self,publickey,websocket):
        self.fernet = cryptography.fernet.Fernet(publickey)
        self.websocket = websocket
        
    def send_json(self,data):
        self.websocket.send(self.fernet.encrypt(json.dumps(data).encode("utf-8")))
    
    def recv_json(self):
        return json.loads(self.fernet.decrypt(self.websocket.recv()).decode("utf-8"))

    def send(self,data):
        self.websocket.send(self.fernet.encrypt(data))
    
    def recv(self):
        return self.fernet.decrypt(self.websocket.recv())
    
    def send_str(self,data):
        self.websocket.send(self.fernet.encrypt(data))
    
    def recv_str(self):
        return self.fernet.decrypt(self.websocket.recv())

conn = connect("ws://localhost:6398")
encrypt = Encrypter(conn.recv(),conn)

data = encrypt.recv_json()
authmode = data["type"]
authorized = None
if authmode == "signup":
    if data["message"] == "username":
        print("This server is new to Bluelink and has no users in the database.")
        print("Please make a user for this Bluelink server:\n")
        username = input("Username: ")
        encrypt.send_json({"type":"signup","username":username})
        data = encrypt.recv_json()
        if data["type"] == "signup":
            while True:
                if data["message"].split("*")[0] == "password":
                    password = getpass.getpass("Password: ")
                    encrypt.send_json({"type":"signup","password":password})
                    data = encrypt.recv_json()
                    
                    if data["message"] == "password-confirm":
                        password_confim = getpass.getpass("Confirm Password: ")
                        encrypt.send_json({"type":"signup","password":password_confim})
                        data = encrypt.recv_json()
                        if data["type"] == "auth-success":
                            print("Account created")
                            print("Login successful")
                            break
                        else:
                            print("Passwords do not match.")
                    else:
                        conn.close()
                else:
                    conn.close()
        elif data["type"] == "signin":
            signinmethods = list(data["message"].split("*")[1])
            method = None
            stp = True
            while stp:
                print(f"This Bluelink server supports muliple sign in methods: {signinmethods}")
                methodinput = pyinputplus.inputChoice(signinmethods,f"Select a method (pick by number by each signinmethod 1/{len(signinmethods)}): ")
                try:
                    method = signinmethods[int(methodinput)]
                    stp = False
                except:
                    print("Not a method.")
                

elif authmode == "signin":
    pass
else:
    pass