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

try:
    import threading
except ImportError:
    print 'Failed to import module threading'

try:
    import datetime
except ImportError:
    print 'Failed to import module datetime'

try:
    from random import randrange
except ImportError:
    print 'Failed to import module randrange'

try:
    import ConfigParser
except ImportError:
    print 'Failed to import module ConfigParser'

class InputGuardian:

    processPath = None
    xorgLog = None
    datetimestamp = None

    def __init__(self):
        self.processPath = '/pro'
        self.xorgLog = '/var/log/Xorg.0.log'
        self.datetimestamp = datetime.datetime.now()

    def watch(self):
        whitelist = None

        try:
            Config = ConfigParser.ConfigParser()
            Config.read('config.ini');
            whitelist =  Config.get('config', 'whitelist').split(',')
        except:
            print 'Whitelist not available'

        '''
        processList = self.getProcessList()
        for processID, path in processList.iteritems():
            print self.getProcessName(processID)
        return False
        '''

        '''
        ASCII Header
        '''
        headerMessage  = "\r\n         /\ \r\n"
        headerMessage += "        /  \ \r\n"
        headerMessage += "    InputGuardian\r\n"
        headerMessage += "      / (||) \ \r\n"
        headerMessage += "     /\  /\  /\ \r\n"
        headerMessage += "------------------------"
        print headerMessage

        while True:
            processList = self.getProcessList()

            for processID, path in processList.iteritems():
                processName = self.getProcessName(processID)

                if processName not in whitelist:
                    self.showMessage('Keylogger detected!', 20)
                    exectuableLocation = self.getExecutablePath(processID)
                    call(['kill', processID])
                    message = 'Killed keylogger with processName "' + processName + '" and processID ' + processID + ' at location ' + exectuableLocation
                    print self.datetimestamp.strftime("%Y-%m-%d %H:%M:%S") + ' | ' + message
                    self.showMessage(message, 60)

    def showMessage(self, message, time):
        call(['notify-send', 'InputGuardian', message, '-i', '/home/net/Code/input-guardian/icons/icon.png', '-u', 'critical', '-t', str(time * 1000) ])

    def getProcessList(self):
        processListKeyboard = {}
        processListAll = os.listdir('/proc')

        for processID in sorted(processListAll):

            try:
                int(processID)
            except ValueError:
                continue

            fdDirectory = os.path.join('/proc', processID, 'fd')

            if os.path.exists(fdDirectory):
                for processDirectory in os.listdir(fdDirectory):
                    try:
                        link = os.readlink(os.path.join(fdDirectory, processDirectory))
                    except OSError:
                        continue
                    if link == self.getEventPath():
                        processListKeyboard[processID] = link
        return processListKeyboard

    def getProcessName(self, processID):
        with open('/proc/' + processID + '/stat', 'r') as procStatus:
            result = re.search(r'\([a-zA-Z]*\)', procStatus.read())
            if result:
                return str(result.group(0))[1:-1].lower()

    def getExecutablePath(self, processID):
        return os.path.realpath('/proc/' + processID + '/exe')

    def getEventPath(self):
        result = False
        with open(self.xorgLog, 'r') as content:
            for line in content:
                if line.find('evdev') != -1 and line.find('keyboard') != -1:
                    path = re.search(r'\/dev\/input\/event[0-9]', line)
                    if path:
                        return str(path.group(0))

inputGuardian = InputGuardian()
inputGuardian.watch()
