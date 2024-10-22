import cryptography.fernet
import websockets, cryptography, json, sqlite3, bcrypt, uuid
from websockets.sync.server import serve, ServerConnection

connectedclients = []
host = "0.0.0.0"
port = 6398
database = sqlite3.connect('bluelink.db')

cursor = database.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY NOT NULL,
    uuid TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
)
''')
database.commit()
connectioncache = {}
signinmethods = ["signin","passkey"]

def handler(websocket: ServerConnection):
    authicated = False
    publickey = cryptography.fernet.Fernet.generate_key()
    fernet = cryptography.fernet.Fernet(publickey)
    websocket.send(publickey)

    def _send_json(data):
        websocket.send(fernet.encrypt(json.dumps(data).encode("utf-8")))
    
    def _recv_json():
        return json.loads(fernet.decrypt(websocket.recv())).decode("utf-8")

    def _send_str(data):
        websocket.send(fernet.encrypt(data.encode("utf-8")))
    
    def _recv_str():
        return fernet.decrypt(websocket.recv()).decode("utf-8")
    
    def _send_str(data):
        websocket.send(fernet.encrypt(data))
    
    def _recv_str():
        return fernet.decrypt(websocket.recv())

    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    
    if count == 0:
        _send_json({"type":"signup","message":"username"})
        while True:
            data = _recv_json()
            if data["type"] == "signup":
                username = data["username"]
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username))
                count = cursor.fetchone()[0]
                if count > 0:
                    uuidstr = str(uuid.uuid4())
                    break
                else:
                    _send_json({"type":"signup","message":"username*exists"})
            else:
                _send_json({"type":"error","message":"Illegal operation. Terminating Connection"})
                websocket.close()
        
        _send_json({"type":"signup","message":"password"})
        while True:
            data = _recv_json()
            if data["type"] == "signup":
                password = data["message"]
                _send_json({"type":"signup","message":"password-confirm"})
                data = _recv_json()
                if data["type"] == "signup":
                    if data["message"] == password:
                        saltpassword = bcrypt.gensalt()
                        hashed_password = bcrypt.hashpw(password.encode("utf-8"),saltpassword)
                        cursor.execute('''
                        INSERT INTO users (username, uuid, hashed_password) 
                        VALUES (?, ?, ?)
                        ''', (username, uuidstr, hashed_password))
                        authicated = True
                        _send_json({"type":"signup","message":"accepted"})
                        break
                    else:
                        _send_json({"type":"signup","message":"retry*password-confirm"})
                        
            else:
                _send_json({"type":"error","message":"Illegal operation. Terminating Connection"})
                websocket.close()
        
    else:
        _send_json({"type":"signin","message":f"methods*{signinmethods}"})
        returndata = _recv_json()
        
        if returndata["type"] == "signin":
            pass
        else:
            _send_json({"type":"error","message":"Illegal operation. Terminating Connection"})
            websocket.close()
        
        if returndata["message"] == "normal":
            _send_json({"type":"signin","message":"username"})
            returndata = _recv_json()
            if returndata["type"] == "signin":
                while True:
                    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username))
                    count = cursor.fetchone()[0]
                    if count > 0:
                        _send_json({"type":"password","message":"password"})
                        break
                    else:
                        _send_json({"type":"signin","message":"username*doesnotexist"})
                
                attempts = 3
                while True:
                    returndata = _recv_json()
                    
            else:
                _send_json({"type":"error","message":"Illegal operation. Terminating Connection"})
                websocket.close()
        elif returndata["message"] == "passkey":
            pass
        else:
            pass
    try:
        connectedclients.append(websocket)
        connectioncache[str(websocket.id)] = {}
        
        #Actual connection here
        pass
    except:  # noqa: E722
        connectedclients.remove(websocket)


websocket = serve(handler=handler,host=host,port=port)
try:
    websocket.serve_forever()
except:
    database.close()