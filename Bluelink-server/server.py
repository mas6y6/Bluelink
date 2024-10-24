import cryptography.fernet
import websockets, cryptography, json, sqlite3, bcrypt, uuid, re
from websockets.sync.server import serve, ServerConnection
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import certifi, ssl, socket

connectedclients = []
host = "0.0.0.0"
port = 6398

print(certifi.where())

print("Starting database")
database = sqlite3.connect('bluelink.db')

cursor = database.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY NOT NULL,
    uuid TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
)
''')
cursor.execute('PRAGMA journal_mode=WAL')
database.commit()
database.close()
connectioncache = {}
signinmethods = ["signin","passkey"]
othersignin = None
sslfile = None

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

def handler(websocket: ServerConnection):
    authorized = False
    sessionid = None
    publickey = cryptography.fernet.Fernet.generate_key()
    websocket.send(publickey)
    database = sqlite3.connect('bluelink.db')
    cursor = database.cursor()
    
    encrypt = Encrypter(publickey,websocket)

    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    
    if count == 0:
        encrypt.send_json({"type":"signup","message":"username"})
        while True:
            data = encrypt.recv_json()
            if data["type"] == "signup":
                username = data["username"]
                if not re.match(r'^[a-zA-Z0-9_]+$', username):
                    encrypt.send_json({"type":"error","message":"Invalid username format"})
                    websocket.close()
                else:
                    uuidstr = str(uuid.uuid4())
                    break
            else:
                encrypt.send_json({"type":"error","message":"Illegal operation. Terminating Connection"})
                websocket.close()
        
        encrypt.send_json({"type":"signup","message":"password"})
        while True:
            data = encrypt.recv_json()
            if data["type"] == "signup":
                password = data["password"]
                encrypt.send_json({"type":"signup","message":"password-confirm"})
                data = encrypt.recv_json()
                if data["type"] == "signup":
                    if data["password"] == password:
                        saltpassword = bcrypt.gensalt()
                        hashed_password = bcrypt.hashpw(password.encode("utf-8"),saltpassword)
                        cursor.execute('''
                        INSERT INTO users (username, uuid, hashed_password) 
                        VALUES (?, ?, ?)
                        ''', (username, uuidstr, hashed_password))
                        authorized = True
                        sessionid = str(uuid.uuid4())
                        encrypt.send_json({"type":"auth-success","message":"authorized","sessionid":sessionid})
                        break
                    else:
                        encrypt.send_json({"type":"signup","message":"password-confirm*retry"})
                        
            else:
                encrypt.send_json({"type":"error","message":"Illegal operation. Terminating Connection"})
                websocket.close()
        
    else:
        encrypt.send_json({"type":"signin","message":f"methods*{signinmethods}"})
        returndata = encrypt.recv_json()
        
        if returndata["type"] == "signin":
            pass
        else:
            encrypt.send_json({"type":"error","message":"Illegal operation. Terminating Connection"})
            websocket.close()
        
        if returndata["message"] == "normal":
            encrypt.send_json({"type":"signin","message":"username"})
            returndata = encrypt.recv_json()
            if returndata["type"] == "signin":
                while True:
                    if not re.match(r'^[a-zA-Z0-9_]+$', username):
                        encrypt.send_json({"type":"error","message":"Invalid username format"})
                        websocket.close()
                    
                    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username))
                    count = cursor.fetchone()[0]
                    if count > 0:
                        cursor.execute('''
                            SELECT username, uuid, hashed_password 
                            FROM users 
                            WHERE username = ?
                        ''', (username))
                        userdata = cursor.fetchone()
                        encrypt.send_json({"type":"password","message":"password"})
                        break
                    else:
                        encrypt.send_json({"type":"signin","message":"username*doesnotexist"})
                
                attempts = 3
                while True:
                    returndata = encrypt.recv_json()
                    if bcrypt.checkpw(returndata["password"],userdata[3]):
                        authorized = True
                        sessionid = str(uuid.uuid4())
                        encrypt.send_json({"type":"auth-success","message":"authorized","sessionid":sessionid})
                        break
                    else:
                        encrypt.send_json({"type":"signin","message":f"password*retry*{attempts}"})
                
                if othersignin:
                    returndata = othersignin(encrypt,websocket)
                    if returndata:
                        authorized = True
                        sessionid = str(uuid.uuid4())
                        encrypt.send_json({"type":"auth-success","message":"authorized","sessionid":sessionid})
                    else:
                        authorized = False
            else:
                encrypt.send_json({"type":"error","message":"Illegal operation. Terminating Connection"})
                websocket.close()
        elif returndata["message"] == "passkey":
            pass
        else:
            pass

    try:
        if authorized:
            connectedclients.append(websocket)
            connectioncache[str(websocket.id)] = {"sessionid":sessionid,"extradata":[],"extraconnections":[]}
        else:
            encrypt.send_json({"type":"error","message":"Please authorize to access this server"})
        #Actual connection here
        pass
    except Exception as e:  # noqa: E722
        encrypt.send_json({"type":"error","message":e})
        connectedclients.remove(websocket)


print("Started Bluelink")
websocket = serve(handler=handler,host=host,port=port,ssl=sslfile)
try:
    websocket.serve_forever()
except:
    database.close()