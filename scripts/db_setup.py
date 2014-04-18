import rethinkdb as r

def db_cmd(cmd):
  try:
    cmd.run()
  except:
    pass
  pass

common_guids = {
  "7ec6c2b0-3fe3-42a0-16a3-22dd0517c1e8": "PFS_DELL_UEFI_VOLUMES",
  "7439ed9e-70d3-4b65-339e-1963a7ad3c37": "PFS_DELL_INTEL_ME"
}

r.connect("localhost").repl()

db_cmd(r.db_create("uefi"))
uefi = r.db("uefi")

#db_cmd(uefi.table_create("files"))
db_cmd(uefi.table_create("content"))
db_cmd(uefi.table_create("updates"))
db_cmd(uefi.table_create("objects"))
db_cmd(uefi.table_create("lookup"))
db_cmd(uefi.table_create("stats"))

db_cmd(uefi.table("lookup").index_create("guid"))
for guid, name in common_guids.iteritems():
  if uefi.table("lookup").get_all(guid, index= "guid").is_empty().run():
    db_cmd(uefi.table("lookup").insert({"guid": guid}))
  db_cmd(uefi.table("lookup").get_all(guid, index= "guid").\
    update({"guid_name": name}))

db_cmd(uefi.table("updates").index_create("item_id"))
db_cmd(uefi.table("updates").index_create("firmware_id"))
db_cmd(uefi.table("updates").index_create("date"))
db_cmd(uefi.table("updates").index_create("vendor"))

db_cmd(uefi.table("objects").index_create("firmware_id"))
db_cmd(uefi.table("objects").index_create("object_id"))
db_cmd(uefi.table("objects").index_create("guid"))
db_cmd(uefi.table("objects").index_create("size"))
db_cmd(uefi.table("objects").index_create("vendor"))
db_cmd(uefi.table("objects").index_create("type"))

db_cmd(uefi.table("content").index_create("firmware_id"))
db_cmd(uefi.table("content").index_create("object_id"))
db_cmd(uefi.table("content").index_create("guid"))
db_cmd(uefi.table("content").index_create("size"))
db_cmd(uefi.table("content").index_create("vendor"))

db_cmd(uefi.table("stats").index_create("key"))
db_cmd(uefi.table("stats").index_create("type"))
db_cmd(uefi.table("stats").index_create("type_key",
  lambda stat:
    [stat["type"], stat["key"]]
))
