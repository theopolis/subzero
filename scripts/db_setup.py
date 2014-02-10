import rethinkdb as r

r.connect("localhost").repl()
try: r.db_create("uefi").run()
except: pass
try: r.db("uefi").table_create("files").run()
except: pass
try: r.db("uefi").table_create("updates").run()
except: pass
try: r.db("uefi").table_create("objects").run()
except: pass

try: r.db("uefi").table_create("lookup").run()
except: pass
