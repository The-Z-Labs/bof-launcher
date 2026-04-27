import icli
import sys
import json
import http.client
import urllib.parse
from pathlib import Path
import yaml

C2_HOST="127.0.0.1:8000"
YAML_FILE="BOF-Z-Labs.yaml"

bofs = []
implants = []

# dict of BOFs documentation. bofName is a key and dict of BOF yaml doc entry is a value
# populated at startup in processBofDocYaml() function
BOF_DOCS = dict()

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


# Implants functions


def showImplantInfo(implantSN):
    print("Implant: " + implantSN)
    print("Task: " + implantSN)
    print("Status: " + implantSN)

def showImplantStatus(implantSN):

    try:
        param = urllib.parse.urlencode({'implant': implantSN})
        conn = http.client.HTTPConnection(C2_HOST)
        conn.request("GET", "/tasking/implants?{}".format(param))
        response = conn.getresponse()

        task_status = json.loads(response.read())

        print("Implant (implantSN: {})".format(implantSN))

        pendingTasksN = task_status['pendingTasksN']
        assignedTasksN = task_status['assignedTasksN']
        completedTasksN = task_status['completedTasksN']
        errTasksN = task_status['errTasksN']
        last_taskID = task_status['last_taskID']
        last_task_command = task_status['last_task_command']
        last_task_output = task_status['last_task_output']

        print()
        print("Number of successfully completed tasks: " + str(completedTasksN))
        print("Number of tasks resulted with error(s): " + str(errTasksN))
        print("Number of running tasks: " + str(assignedTasksN))
        print("Number of tasks pending on server: " + str(pendingTasksN))
        print()

        print("Last task (taskID: {})".format(last_taskID))
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

        print("implant SN |", "first Seen At |", "last seen at |", "implantIdentity")
        for keySN, record in records.items():
            implants.append(keySN)
            print(keySN, record['firstSeenAt'], record['lastSeenAt'], record['implantIdentity'])

    except http.client.RemoteDisconnected as e:
        print(f"Oops! The server disconnected unexpectedly: {e}")
    except http.client.HTTPException as e:
        print(f"A general HTTP error occurred: {type(e).__name__}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

### BOFs functions

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
            if _command == 'list':
                res = listingBofs()
                for b in res:
                    print(b)
            if _command == 'exec-inline':
                argv = ""
                if kwargs['argv']:
                    argv = kwargs['argv']
                execBof("inline", kwargs['bofName'], kwargs['implantSN'], argv)
            if _command == 'exec-thread':
                execBof("thread", kwargs['bofName'], kwargs['implantSN'], kwargs['argv'])
        elif _object == 'exec_shellcode':
            print('exec_shellcode')
        elif _object == 'implant':
            if _command == 'list':
                resp = getImplantsList()
                print(resp)
            if _command == 'info':
                resp = showImplantInfo(kwargs['implantSN'])
                print(resp)
            if _command == 'status':
                showImplantStatus(kwargs['implantSN'])

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

sp = ap.add_subparsers(dest='_object', metavar='object', help='Object')

# Implant commands

ap_implant = sp.add_parser('implant', help='Implants')
sp_implant = ap_implant.add_subparsers(dest='_command',
                                       metavar='command',
                                       help='Command')

sp_implant_list = sp_implant.add_parser('list', help='Lists implants that beaconed at least once')

sp_implant_info = sp_implant.add_parser('info', help='Show details about the implant')
sp_implant_info.add_argument(
    'implantSN', metavar='IMPLANT', help='Implant SN').completer = ComplImplants()

sp_implant_status = sp_implant.add_parser('status', help='Show current status of selected IMPLANT')
sp_implant_status.add_argument(
    'implantSN', metavar='IMPLANT', help='Implant SN').completer = ComplImplants()

# BOF commands

ap_bof = sp.add_parser('bof', help='BOF execution routines')
sp_bof = ap_bof.add_subparsers(dest='_command',
                                       metavar='command',
                                       help='Command')

sp_bof_list = sp_bof.add_parser('list', help='Lists available BOFs')


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

sp_bof_exec = sp_bof.add_parser('exec-thread', help='Execution of a chosen BOF in a separate thread')
sp_bof_exec = sp_bof.add_parser('spawn', help='Execution of a chosen BOF inside of a sacrificial process')
sp_bof_exec = sp_bof.add_parser('inject', help='Injecting chosen BOF to a chosen (running) process')

ap.sections = {'implant': [], 'bof': []}

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
