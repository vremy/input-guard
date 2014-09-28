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

inputGuardian = InputGuardian()
inputGuardian.watch()
