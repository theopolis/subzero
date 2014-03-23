import rethinkdb as r

def db_cmd(cmd):
  try:
    cmd.run()
  except:
    pass
  pass

r.connect("localhost").repl()

db_cmd(r.db_create("uefi"))
uefi = r.db("uefi")

#db_cmd(uefi.table_create("files"))
db_cmd(uefi.table_create("content"))
db_cmd(uefi.table_create("updates"))
db_cmd(uefi.table_create("objects"))
db_cmd(uefi.table_create("lookup"))

db_cmd(uefi.table("updates").index_create("item_id"))
db_cmd(uefi.table("updates").index_create("firmware_id"))

db_cmd(uefi.table("objects").index_create("firmware_id"))
db_cmd(uefi.table("objects").index_create("object_id"))
db_cmd(uefi.table("objects").index_create("guid"))

db_cmd(uefi.table("content").index_create("firmware_id"))
db_cmd(uefi.table("content").index_create("object_id"))

