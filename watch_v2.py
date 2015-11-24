import pyinotify,subprocess

def onChange(ev):
    cmd = ['/bin/echo', 'File', ev.pathname, 'changed']
    subprocess.Popen(cmd).communicate()
    with open('/root/Documents/python/pyinotify/server.py', 'r') as f:
    	print f.read()
    f.close()
    return

wm = pyinotify.WatchManager()
wm.add_watch('/root/Documents/python/pyinotify/', pyinotify.IN_CLOSE_WRITE, onChange)
notifier = pyinotify.Notifier(wm)
notifier.loop()
