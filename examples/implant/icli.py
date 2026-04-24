__author__ = 'Altertech'
__license__ = 'MIT'
__version__ = '0.0.10'

import argparse

_REPEAT_ONCE = 1
_REPEAT_CONT = 2
_REPEAT_CONT_CLS = 3


class ArgumentParser(argparse.ArgumentParser):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sections = {}
        self.current_section = []
        self.ps = 'z-beac0n> '
        self.interactive_quit = ['q', 'exit', 'quit']
        self.interactive_help = ['h', 'help', '?']
        self.interactive_global_commands = {}
        self.interactive_history_file = ''
        self.interactive_history_length = 100
        self.send_args_as_dict = True

    def run(self, **kwargs):
        '''
        Process commands. Should always be overrided
        '''
        print(kwargs)

    def get_interactive_prompt(self):
        '''
        Returns interactive prompt. Override to set custom prompt
        '''
        if self.current_section:
            ps = '/'.join(self.current_section) + self.ps
        else:
            ps = self.ps
        return ps

    def print_global_help(self):
        '''
        Prints help for global commands
        '''
        return

    def print_repeat_title(self, command, interval):
        '''
        Prints title of command repeater
        '''
        import datetime
        t = datetime.datetime.now().strftime('%Y-%m-%d %T')
        print('{}  {}  (interval {} sec)'.format(t, command, interval))

    def handle_interactive_exception(self):
        '''
        Called if exception is occured in command
        '''
        raise

    def handle_interactive_parser_exception(self):
        '''
        Called if argparse exception is occured
        '''
        return

    def clear_screen(self):
        import platform
        import os
        if platform.system().lower() == 'windows':
            os.system('cls')
        else:
            os.system('clear')

    def interactive_completer(self, text, state):
        import shlex
        inp = shlex.split(text)
        if ';' in inp:
            rv = inp.copy()
            rv.reverse()
            spindex = len(rv) - rv.index(';') - 1
            gpfx = ' '.join(inp[:spindex]) + ' ; '
            text = ' '.join(inp[spindex + 1:])
        else:
            gpfx = ''
        if text and text.startswith('/'):
            current_section = []
            text = text[1:]
            pfx = '/'
        else:
            current_section = self.current_section
            pfx = ''
        result = self._i_completer.rl_complete(('' if not \
                current_section else \
                (' '.join(current_section) + ' ')) + text, state)
        if self.current_section:
            cs = ' '.join(current_section) + ' '
            if result and result.startswith(cs):
                result = result[len(cs):]
        return gpfx + pfx + result

    def launch(self, args=None):
        import argcomplete
        argcomplete.autocomplete(self)
        sect = self.sections
        sect_help = True
        if not args:
            import sys
            args = sys.argv[1:]
        for a in args:
            if a in sect:
                try:
                    sect = sect[a]
                except TypeError:
                    pass
            else:
                sect_help = False
                break
        if sect_help: args.append('-h')
        a = self.parse_args(args)
        if self.send_args_as_dict:
            self.run(**a.__dict__)
        else:
            self.run(a)

    def batch(self, stream):
        return self.interactive(stream=stream)

    def interactive(self, stream=None):

        import readline
        import argcomplete
        import shlex
        import time
        import os
        import sys

        def save_history():
            if self.interactive_history_file:
                try:
                    readline.write_history_file(
                        os.path.expanduser(self.interactive_history_file))
                except:
                    pass

        if stream:
            input_strings = stream.readlines()
            if not input_strings:
                return
            sidx = 0
        else:
            self._i_completer = argcomplete.CompletionFinder(
                self,
                default_completer=argcomplete.completers.SuppressCompleter())
            readline.set_completer_delims('')
            readline.set_completer(self.interactive_completer)
            readline.parse_and_bind('tab: complete')
            readline.set_history_length(self.interactive_history_length)
            if self.interactive_history_file:
                try:
                    readline.read_history_file(
                        os.path.expanduser(self.interactive_history_file))
                except:
                    pass
        while True:
            try:
                if stream:
                    try:
                        input_str = input_strings[sidx]
                    except IndexError:
                        return
                    if sidx: print()
                    sidx += 1
                else:
                    input_str = input(self.get_interactive_prompt())
                try:
                    input_arr = shlex.split(input_str)
                except:
                    print('invalid input', file=sys.stderr)
                    input_arr = None
                if not input_arr: continue
                if input_arr[-1].startswith('|'):
                    repeat = input_arr.pop()[1:]
                    if repeat.startswith('c'):
                        do_repeat = _REPEAT_CONT_CLS
                        repeat = repeat[1:]
                    else:
                        do_repeat = _REPEAT_CONT
                    try:
                        repeat_seconds = float(repeat)
                    except:
                        self.handle_interactive_exception()
                        continue
                else:
                    do_repeat = _REPEAT_ONCE
                if ';' in input_arr:
                    size = len(input_arr)
                    idx_list = [
                        idx + 1
                        for idx, val in enumerate(input_arr)
                        if val == ';'
                    ]
                    input_val = [
                        input_arr[i:j]
                        for i, j in zip([0] + idx_list, idx_list + (
                            [size] if idx_list[-1] != size else []))
                    ]
                else:
                    input_val = [input_arr]
                if do_repeat == _REPEAT_CONT_CLS:
                    input_str = ' '.join(input_arr)
                    self.clear_screen()
                    self.print_repeat_title(input_str, repeat_seconds)
                while do_repeat:
                    if do_repeat == _REPEAT_ONCE:
                        do_repeat = 0
                    for pidx, parsed in enumerate(input_val):
                        parsed = parsed.copy()
                        if parsed[-1] == ';':
                            parsed.pop()
                        if not parsed: continue
                        if len(parsed) == 1:
                            if parsed[0] == '/':
                                self.current_section = []
                                continue
                            elif parsed[0] == '..':
                                try:
                                    self.current_section.pop()
                                except IndexError:
                                    pass
                                continue
                            elif parsed[0] in self.interactive_help:
                                self.print_global_help()
                                parsed[0] = '-h'
                            elif parsed[0] in self.interactive_quit:
                                if not stream: save_history()
                                print()
                                return
                        # try to jump to section
                        jump_to = []
                        sect = self.sections
                        if parsed[0] in self.interactive_global_commands:
                            try:
                                self.interactive_global_commands[parsed[0]](
                                    *parsed)
                            except:
                                self.handle_interactive_exception()
                            continue
                        if parsed[0].startswith('/'):
                            root_cmd = True
                            parsed[0] = parsed[0][1:]
                        else:
                            root_cmd = False
                            for i in self.current_section:
                                try:
                                    sect = sect[i]
                                except TypeError:
                                    break
                        for p in parsed:
                            if sect and p in sect:
                                jump_to.append(p)
                            else:
                                jump_to = None
                                break
                            try:
                                sect = sect[p]
                            except TypeError:
                                sect = None
                        if jump_to:
                            if root_cmd:
                                self.current_section = jump_to
                            else:
                                self.current_section += jump_to
                            continue
                        if not root_cmd and self.current_section:
                            if len(parsed) == 1 and parsed[0] == '-h':
                                args = self.current_section + parsed
                            else:
                                args = []
                                cs_added = False
                                for p in parsed:
                                    if not p.startswith('-') and not cs_added:
                                        cs_added = True
                                        if not p.startswith('/'):
                                            args += self.current_section
                                        else:
                                            args.append(p[1:])
                                            continue
                                    args.append(p)
                        else:
                            args = parsed
                        try:
                            a = self.parse_args(args)
                        except:
                            self.handle_interactive_parser_exception()
                            continue
                        try:
                            if self.send_args_as_dict:
                                self.run(**a.__dict__)
                            else:
                                self.run(a)
                        except:
                            self.handle_interactive_exception()
                        if pidx < len(input_val) - 1:
                            print()
                    if do_repeat:
                        time.sleep(repeat_seconds)
                        if do_repeat == _REPEAT_CONT_CLS:
                            self.clear_screen()
                            self.print_repeat_title(input_str, repeat_seconds)
                        else:
                            print()
            except KeyboardInterrupt:
                print()
                pass
            except EOFError:
                if self.current_section:
                    self.current_section.pop()
                    print()
                    continue
                else:
                    save_history()
                    print()
                    return
