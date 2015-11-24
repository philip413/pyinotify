import pyinotify,subprocess


class mod_handler(pyinotify.ProcessEvent):
	def process_IN_MODIFY(self, ev):
	    cmd = ['/bin/echo', 'File', ev.pathname, 'changed']
	    subprocess.Popen(cmd).communicate()
	    with open('/root/Documents/python/pyinotify/server.py', 'r') as f:
	    	print f.read()
	    f.close()

handler = mod_handler()
wm = pyinotify.WatchManager()
notifier = pyinotify.Notifier(wm, handler)
wm.add_watch('/root/Documents/python/pyinotify/', pyinotify.IN_MODIFY)
notifier.loop()