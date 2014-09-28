#!/usr/bin/env python 

try:
    import os
except ImportError:
    print 'Failed to import module os'

try:
    import re
except ImportError:
    print 'Failed to import module re'

class InputGuardian:

    procPath = None
    xorgLog = None

    def __init__(self):
        self.procPath = '/pro'
        self.xorgLog = '/var/log/Xorg.0.log'

    def watch(self):
        pids = os.listdir('/proc')

        for pid in sorted(pids):

            try:
                int(pid)
            except ValueError:
                continue

            fd_dir = os.path.join('/proc', pid, 'fd')

            for file in os.listdir(fd_dir):
                try:
                    link = os.readlink(os.path.join(fd_dir, file))
                except OSError:
                    continue
                print pid, link

    def getEventPath(self):
        result = False
        with open(self.xorgLog, 'r') as content:
            for line in content:
                if line.find('evdev') != -1 and line.find('keyboard') != -1:
                    path = re.search(r'\/dev\/input\/event[0-9]', line)
                    if path:
                        result = str(path.group(0))
        return result

inputGuardian = InputGuardian()
inputGuardian.watch()
