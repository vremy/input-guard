#!/usr/bin/env python 

try:
    import os
except ImportError:
    print 'Failed to import module os'

try:
    import re
except ImportError:
    print 'Failed to import module re'

try:
    from subprocess import call
except ImportError:
    print 'Failed to import module call'


'''
/etc/modprobe.d/blacklist.conf
pcspkr
'''

class InputGuardian:

    procPath = None
    xorgLog = None

    def __init__(self):
        self.procPath = '/pro'
        self.xorgLog = '/var/log/Xorg.0.log'

    def watch(self):
        procList = self.getProcessList()

        if len(procList) > 1:
            time = 10 # time in seconds
            self.showMessage('Keylogger detected!', 20)

        for procID, path in procList.iteritems():
            procName = self.getProcessName(procID)
            if procName != 'xorg':
                call(['kill', procID])
                self.showMessage('Killed keylogger with process ' + procName + ' and pid ' + procID, 30)

    def showMessage(self, message, time):
        call(['notify-send', 'InputGuardian', message, '-i', '/home/net/Code/input-guardian/icons/warning.png', '-u', 'critical', '-t', str(time * 1000) ])

    def getProcessList(self):
        procList = {}
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
                if link == self.getEventPath():
                    procList[pid] = link

        return procList

    def getProcessName(self, procID):
        with open('/proc/' + procID + '/stat', 'r') as procStatus:
            result = re.search(r'\([a-zA-Z]*\)', procStatus.read())
            if result:
                return str(result.group(0))[1:-1].lower()


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
