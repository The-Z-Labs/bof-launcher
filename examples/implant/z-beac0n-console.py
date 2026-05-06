import icli
import sys
import json
import http.client
import urllib.parse
from pathlib import Path
import yaml
import texttable

C2_HOST="127.0.0.1:8000"
YAML_FILE="BOF-Z-Labs.yaml"

bofs = []
implants = []

# dict of BOFs documentation. bofName is a key and dict of BOF yaml doc entry is a value
# populated at startup in processBofDocYaml() function
BOF_DOCS = dict()

def displayTaskID(taskID):
    return taskID

def getArgSpecFromDoc(bof_doc_entry):
    argsSpec = ""

    if not 'arguments' in bof_doc_entry:
        return argsSpec

    for argument in bof_doc_entry['arguments']:
        if argument['type'] == "string":
            argsSpec += "z"
        if argument['type'] == "wstring":
            argsSpec += "Z"
        elif argument['type'] == "integer":
            argsSpec += "i"
        elif argument['type'] == "short":
            argsSpec += "s"

    return argsSpec

def getRetValFromDoc(bof_doc_entry):
    if not 'errors' in bof_doc_entry:
        return "void"

    return "u8"

# parsing BOF YAML collection file for available BOFs
def processBofDocYaml():
    yamlFile = Path(YAML_FILE)
    with open(yamlFile) as f:
        for bofMetadata in yaml.safe_load_all(f):

            # populate global list of available BOFs
            bofs.append(bofMetadata['name'])

            # populate global dict of doc bof_entries where key = bofname
            bof_entry = dict()
            BOF_DOCS[bofMetadata['name']] = bofMetadata

#
# Implants functions
#

def showImplantInfo(implantSN):
    print()
    print("Implant ID: " + implantSN)
    print("First seen at: TODO")
    print("Last seen at: TODO")
    print("Implant identity string: TODO")
    print()

def showImplantStatus(implantSN):

    try:
        param = urllib.parse.urlencode({'implant': implantSN})
        conn = http.client.HTTPConnection(C2_HOST)
        conn.request("GET", "/tasking/implants?{}".format(param))
        response = conn.getresponse()

        task_status = json.loads(response.read())

        print("Implant (implantSN: {})".format(implantSN))

        pendingTasksN = task_status['pendingTasksN']
        inprogressTasksN = task_status['inprogressTasksN']
        completedTasksN = task_status['completedTasksN']
        errTasksN = task_status['errTasksN']
        last_taskID = task_status['last_taskID']
        last_task_command = task_status['last_task_command']
        last_task_output = task_status['last_task_output']

        print()
        print("Number of successfully completed tasks: " + str(completedTasksN))
        print("Number of tasks resulted with error(s): " + str(errTasksN))
        print("Number of running tasks: " + str(inprogressTasksN))
        print("Number of tasks pending on server: " + str(pendingTasksN))
        print()

        if last_taskID != "":
            print("Last task (taskID: {})".format(displayTaskID(last_taskID)))
            print()
            print(last_task_command)
            print()
            print("Output: ")
            print()
            print(last_task_output)


    except http.client.RemoteDisconnected as e:
        print(f"Oops! The server disconnected unexpectedly: {e}")
    except http.client.HTTPException as e:
        print(f"A general HTTP error occurred: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

    

# get content of ImplantDict from C2 server
def getImplantsList():
    try:
        conn = http.client.HTTPConnection(C2_HOST)
        conn.request("GET", "/tasking/implants")
        response = conn.getresponse()

        records = json.loads(response.read())

        tableObj = texttable.Texttable(0)
        tableObj.set_deco(texttable.Texttable.HEADER)
        tableObj.set_cols_dtype(["t", "t", "t", "t"])
        #tableObj.set_cols_valign(["t", "t", "t", "t"])
        tableObj.add_rows([["Implant ID", "First seen at", "Last seen at", "Implant identity string"]], header=True)

        for keySN, record in records.items():
            implants.append(keySN)
            tableObj.add_row([keySN, record['firstSeenAt'], record['lastSeenAt'], record['implantIdentity']])

        print(tableObj.draw())
        print()

    except http.client.RemoteDisconnected as e:
        print(f"Oops! The server disconnected unexpectedly: {e}")
    except http.client.HTTPException as e:
        print(f"A general HTTP error occurred: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

#
# Tasks functions
#
TASK_STATUS = [
        'UNKNOWN',
        'PENDING',
        'IN PROGRESS',
        'COMPLETED',
        'FAILED',
        ]

def getTasksList(implantSN):
    try:
        if implantSN != "" and implantSN in implants:
            param = urllib.parse.urlencode({'implant': implantSN})
            url = "/tasking/tasks?{}".format(param)
        else:
            url = "/tasking/tasks"

        conn = http.client.HTTPConnection(C2_HOST)
        conn.request("GET", url)
        response = conn.getresponse()

        try:
            records = json.loads(response.read())
        except json.JSONDecodeError as e:
            print("Invalid JSON syntax:", e)

        tableObj = texttable.Texttable(0)
        tableObj.set_deco(texttable.Texttable.HEADER)
        tableObj.set_cols_dtype(["t", "t", "t", "t", "t"])
        #tableObj.set_cols_valign(["t", "t", "t", "t"])
        tableObj.add_rows([["Task ID", "Implant ID", "Input Command", "Execution Mode", "Task State"]], header=True)

        print()
        for entry in records:
            tableObj.add_row([displayTaskID(entry['taskID']), entry['implantID'], entry['task_command'], entry['exec_mode'], TASK_STATUS[entry['task_state']]])

        print(tableObj.draw())

    except http.client.RemoteDisconnected as e:
        print(f"Oops! The server disconnected unexpectedly: {e}")
    except http.client.HTTPException as e:
        print(f"A general HTTP error occurred: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
        return ""

def showTaskInfo(taskID):
    try:
        param = urllib.parse.urlencode({'id': taskID})
        url = "/tasking/task?{}".format(param)

        conn = http.client.HTTPConnection(C2_HOST)
        conn.request("GET", url)
        response = conn.getresponse()

        try:
            record = json.loads(response.read())
        except json.JSONDecodeError as e:
            print("Invalid JSON syntax:", e)

        for taskInfo in record:
            tstate = taskInfo['task_state']
            print("Task ID: {}".format(displayTaskID(taskInfo['taskID'])))
            print("Task State: {}".format(TASK_STATUS[tstate]))
            print("Execution Mode: {}".format(taskInfo['exec_mode']))
            print("Task Input:")

            print()
            print(taskInfo['task_command'])
            print()

            if TASK_STATUS[tstate] == "COMPLETED":
                print("Task Output: ")
                print()
                print(taskInfo['task_output'])
            elif TASK_STATUS[tstate] == "FAILED":
                # TODO: get string from YAML realted to a given return code
                print("Return Status: {}".format(taskInfo['task_retstatus']))

    except http.client.RemoteDisconnected as e:
        print(f"Oops! The server disconnected unexpectedly: {e}")
    except http.client.HTTPException as e:
        print(f"A general HTTP error occurred: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()
        return ""

#
# BOFs functions
#

def execBof(TYPE, bof, implantSN, argv):
    try:
        conn = http.client.HTTPConnection(C2_HOST)

        headers = {'Content-type': 'application/json'}

        bof_doc_entry = BOF_DOCS[bof]

        bof_header = ""

        if TYPE == "inline":
            bof_header += "inline:"
        elif TYPE == "thread":
            bof_header += "thread:"
        elif TYPE == "spawn":
            bof_header += "process:"

        args_spec = getArgSpecFromDoc(bof_doc_entry)
        bof_header += args_spec
        bof_header += ":"

        retVal_spec = getRetValFromDoc(bof_doc_entry)
        bof_header += retVal_spec

        print(bof_header)

        implant_task = {
            "SN": implantSN,
            "name": "bof:" + str(bof),
            "header": bof_header,
        }

        if argv != "":
            implant_task['argv'] = argv

        task_json = json.dumps(implant_task)

        conn.request("POST", "/tasking", task_json, headers)
        response = conn.getresponse()

    except http.client.RemoteDisconnected as e:
        print(f"Oops! The server disconnected unexpectedly: {e}")
    except http.client.HTTPException as e:
        print(f"A general HTTP error occurred: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

    print(implantSN, bof)
    print(argv)


def listingBofs():
    return bofs

class ComplImplants():

    def __call__(self, prefix, **kwargs):
        return implants

class ComplBofs():

    def __call__(self, prefix, **kwargs):
        return bofs

class ArgumentParser(icli.ArgumentParser):

    def run(self, _object, _type=None, _command=None, **kwargs):
        if _object == 'bof':
            if _command == 'list' or _command == 'ls':
                res = listingBofs()
                for b in res:
                    print(b)
            if _command == 'exec-inline':
                argv = ""
                if kwargs['argv']:
                    argv = kwargs['argv']
                execBof("inline", kwargs['bofName'], kwargs['implantSN'], argv)
            if _command == 'exec-thread':
                argv = ""
                if kwargs['argv']:
                    argv = kwargs['argv']
                execBof("thread", kwargs['bofName'], kwargs['implantSN'], argv)
            if _command == 'spawn':
                argv = ""
                if kwargs['argv']:
                    argv = kwargs['argv']
                execBof("spawn", kwargs['bofName'], kwargs['implantSN'], argv)
        elif _object == 'shellcode':
            print('exec_shellcode')
        elif _object == 'implant':
            if _command == 'list' or _command == 'ls':
                resp = getImplantsList()
            if _command == 'info':
                resp = showImplantInfo(kwargs['implantSN'])
                print(resp)
            if _command == 'status':
                showImplantStatus(kwargs['implantSN'])
        elif _object == 'task':
            if _command == 'info':
                taskID = kwargs['taskID']
                showTaskInfo(taskID)
            if _command == 'list' or _command == 'ls':
                implantSN = ""
                if kwargs['implant']:
                    implantSN = kwargs['implant']
                resp = getTasksList(implantSN)
                print(resp)

    def print_global_help(self):
        print()

    def handle_interactive_exception(self):
        print('error')
        import traceback
        traceback.print_exc()

    def get_interactive_prompt(self):
        if self.current_section:
            s = '/'.join(self.current_section)
            ps = '[{}] {}'.format(s, self.ps)
        else:
            ps = self.ps
        return ps

    def print_repeat_title(self, command, interval):
        import datetime
        t = datetime.datetime.now().strftime('%Y-%m-%d %T')

        print('{}  {}  (interval {} sec)'.format(t, command, interval))

ap = ArgumentParser(prog='' if len(sys.argv) < 2 else None)

sp = ap.add_subparsers(dest='_object', metavar='', help='')

# Implant commands

ap_implant = sp.add_parser('implant', help='Implants management')
sp_implant = ap_implant.add_subparsers(dest='_command',
                                       metavar='command',
                                       help='Command')

sp_implant_list = sp_implant.add_parser('list', help='Lists implants that beaconed at least once')
sp_implant_list = sp_implant.add_parser('ls', help='The same as "list"')

sp_implant_info = sp_implant.add_parser('info', help='Show details about the implant')
sp_implant_info.add_argument(
    'implantSN', metavar='IMPLANT', help='Implant SN').completer = ComplImplants()

sp_implant_status = sp_implant.add_parser('status', help='Show current status of selected IMPLANT')
sp_implant_status.add_argument(
    'implantSN', metavar='IMPLANT', help='Implant SN').completer = ComplImplants()

# Task commands

ap_task = sp.add_parser('task', help='Tasks history')
sp_task = ap_task.add_subparsers(dest='_command',
                                       metavar='command',
                                       help='Command')

sp_task_list = sp_task.add_parser('list', help='Lists implants that beaconed at least once')
sp_task_ls = sp_task.add_parser('ls', help='The same as "list"')
sp_task_list.add_argument('--implant',
                                 metavar='IMPLANT',
                                 help='Implant serial number (SN)', required=False)
sp_task_ls.add_argument('--implant',
                                 metavar='IMPLANT',
                                 help='Implant serial number (SN)', required=False)

sp_task_info = sp_task.add_parser('info', help='Show details about the task')
sp_task_info.add_argument(
    'taskID', metavar='TASK', help='Task ID')

# Shellcode commands

ap_shellcode = sp.add_parser('shellcode', help='Shellcode execution routines')
sp_shellcode = ap_shellcode.add_subparsers(dest='_command',
                                       metavar='command',
                                       help='Command')

# BOF commands

ap_bof = sp.add_parser('bof', help='BOF execution routines')
sp_bof = ap_bof.add_subparsers(dest='_command',
                                       metavar='command',
                                       help='Command')

sp_bof_list = sp_bof.add_parser('list', help='Lists available BOFs')
sp_bof_list = sp_bof.add_parser('ls', help='The same as "list"')


sp_bof_exec = sp_bof.add_parser('info', help='Show BOF details')


sp_bof_exec.add_argument('implantSN',
                                 metavar='IMPLANT',
                                 help='SN of implant for tasking')
sp_bof_exec.add_argument('bofName',
                                 metavar='BOF',
                                 help='BOF to execute')


sp_bof_exec = sp_bof.add_parser('exec-inline', help='Inline execution of a chosen BOF')
sp_bof_exec.add_argument(
    'implantSN', metavar='IMPLANT', help='Implant SN').completer = ComplImplants()
sp_bof_exec.add_argument(
    'bofName', metavar='BOF', help='BOF name').completer = ComplBofs()

sp_bof_exec.add_argument('--argv',
                                 metavar='ARGV',
                                 help='BOF arguments', required=False)

sp_bof_exec_thread = sp_bof.add_parser('exec-thread', help='Execution of a chosen BOF in a separate thread')
sp_bof_exec_thread.add_argument(
    'implantSN', metavar='IMPLANT', help='Implant SN').completer = ComplImplants()
sp_bof_exec_thread.add_argument(
    'bofName', metavar='BOF', help='BOF name').completer = ComplBofs()

sp_bof_exec_thread.add_argument('--argv',
                                 metavar='ARGV',
                                 help='BOF arguments', required=False)


sp_bof_exec_process = sp_bof.add_parser('spawn', help='Execution of a chosen BOF inside of a sacrificial process')
sp_bof_exec_process.add_argument(
    'implantSN', metavar='IMPLANT', help='Implant SN').completer = ComplImplants()
sp_bof_exec_process.add_argument(
    'bofName', metavar='BOF', help='BOF name').completer = ComplBofs()

sp_bof_exec_process.add_argument('--argv',
                                 metavar='ARGV',
                                 help='BOF arguments', required=False)


sp_bof_exec = sp_bof.add_parser('inject', help='Injecting chosen BOF to a chosen (running) process')

ap.sections = {'implant': [], 'bof': [], 'task': []}

print(
"""
             bb                             00000          
zzzzz        bb        eee    aa aa   cccc 00   00 nn nnn  
  zz  _____  bbbbbb  ee   e  aa aaa cc     00   00 nnn  nn 
 zz          bb   bb eeeee  aa  aaa cc     00   00 nn   nn 
zzzzz        bbbbbb   eeeee  aaa aa  ccccc  00000  nn   nn 
                                                           
"""
)

processBofDocYaml()

if len(sys.argv) > 1:
    ap.launch()
else:
    ap.interactive()
