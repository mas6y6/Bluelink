import cryptography.fernet
import websockets, cryptography, json
from websockets.sync.server import serve, ServerConnection

class Server:
    def __init__(self,host="0.0.0.0",port=6390, ssl=None):
        self.port = port
        self.host = host
        self.ssl = ssl
        self.websocket = None
        self.connectedclients = []
        self.publickey = cryptography.fernet.Fernet.generate_key()
        self.fernet = cryptography.fernet.Fernet(self.publickey)
        self.thread = None
    
    def handler(self, websocket: ServerConnection):
        websocket.send(self.publickey)
        self.connectedclients.append(websocket)

        def _send_json(data):
            websocket.send(self.fernet.encrypt(json.dumps(data).encode("utf-8")))
        
        def _recv_json(data):
            websocket.recv()

        try:
            pass
        except:
            self.connectedclients.remove(websocket)
    
    def start(self):
        self.websocket = serve(handler=self.handler,host=self.host,port=self.port)
        self.websocket.serve_forever()