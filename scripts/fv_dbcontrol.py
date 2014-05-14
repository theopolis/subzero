import argparse, json, os, sys, time
import base64
import copy
import gc
import subprocess

import hashlib
import pydeep
import magic
import pefile

import rethinkdb as r

from utils import red, blue

# Testing
from fv_fileoutput import file_compare

def _dump_data(name, data):
    try:
        with open(name, 'wb') as fh: fh.write(data)
        print "Wrote: %s" % (red(name))
    except Exception, e:
        print "Error: could not write (%s), (%s)." % (name, str(e))

def _object_compare(obj1, obj2):
    content1 = base64.b64decode(obj1)
    content2 = base64.b64decode(obj2)
    min_size = min(len(content1), len(content2))
    max_size = max(len(content1), len(content2))
    change_score = max_size - min_size
    for i in xrange(min_size):
        if content1[i] != content2[i]:
            change_score += 1 
    return change_score   

class Controller(object):

    def command_list_fv(self, db, args):
        ids = db.table("files").pluck("firmware_id").distinct().run()
        for _id in ids:
            info = db.table("updates").filter({"firmware_id": _id["firmware_id"]}).pluck("date", "machine", "name", "version").run()
            print "%s:" % _id["firmware_id"],
            for _machine in info:
                print "%s, %s, %s, %s" % (_machine["date"], _machine["machine"], _machine["name"], _machine["version"])
        pass

    def command_list_files(self, db, args):
        files = db.table("files").filter({"firmware_id": args.fv_id}).pluck("guid", "name", "attrs", "description").order_by(r.row["attrs"]["size"]).run()
        for _file in files: print "%s %s %s (%s)" % (_file["guid"], _file["attrs"]["size"], _file["name"], _file["description"])
        pass

    def _compare_children(self, db, list1, list2, save= False):
        change_score = 0
        added_objects = []
        added_objects_score = 0

        ### Assemble GUID pairs
        children1, children2 = {}, {}
        child_cursor = db.table("objects").get_all(*(list1 + list2)).\
            pluck("id", "size", "object_id", "guid", "children", "order").\
            order_by("order").order_by("size").run()

        has_child = False
        for i, child in enumerate(child_cursor):
            if child["id"] == "4ae16769-cef1-44ec-97d7-13d6d59fdd21":
                has_child = True
            if "guid" not in child:
                #print i, child["size"]
                child["guid"] = min(len(children1.keys()), len(children2.keys()))
                #print child["guid"], child["size"]
            #print i, child["size"], child["guid"]
            if child["id"] in list1:
                if child["guid"] not in children1.keys(): 
                    children1[child["guid"]] = []
                children1[child["guid"]].append(child)
            if child["id"] in list2: 
                if child["guid"] not in children2: 
                    children2[child["guid"]] = []
                children2[child["guid"]].append(child)

        #print children1.keys()
        #print children2.keys()

        objects1, objects2 = [], []
        for guid in children2.keys():
            if guid not in children1:
                print "added guid %s" % guid
                ### This guid/object was added in the update
                added_objects += [c["object_id"] for c in children2[guid]]
                added_objects_score += sum([int(c["size"]) for c in children2[guid]])
                ### Todo: this does not account for nested children in a new update
                continue
            for i in xrange(len(children2[guid])):
                if "children" in children2[guid][i] and len(children2[guid][i]["children"]) > 0:
                    ### There are nested children, compare them individually.
                    if len(children1[guid]) <= i or "children" not in children1[guid][i]:
                        ### There are less grandchildren in the previous update (for this child guid)
                        child_ids = db.table("objects").get_all(*children2[guid][i]["children"]).pluck("object_id").run()
                        nested_change = [
                            int(children2[guid][i]["size"]),
                            [child["object_id"] for child in child_ids],
                            int(children2[guid][i]["size"])
                        ]
                    else:
                        #print red("will compare grandchildren lengths %d %d for guid %s, index %d" % (
                        #    len(children1[guid][i]["children"]), len(children2[guid][i]["children"]), guid, i
                        #    ))
                        nested_change = self._compare_children(db, children1[guid][i]["children"], children2[guid][i]["children"], save= save)
                    
                    change_score += nested_change[0]
                    added_objects += nested_change[1]
                    added_objects_score += nested_change[2]

                    if save:
                        db.table("objects").get(children2[guid][i]["id"]).update({
                            "load_change": {
                                "change_score": nested_change[0],
                                "new_files": nested_change[1],
                                "new_files_score": nested_change[2]
                            }
                        }).run()

                    continue
                elif len(children1[guid]) <= i:
                    added_objects.append(children2[guid][i]["object_id"])
                    added_objects_score += int(children2[guid][i]["size"])
                    change_score += int(children2[guid][i]["size"])
                else:
                    objects1.append(children1[guid][i]) # ["object_id"]
                    objects2.append(children2[guid][i]) # ["object_id"]

        ### If there are objects, compare the content
        content1, content2 = [], []
        if len(objects1) + len(objects2) > 0:
            content_cursor = db.table("content").\
                get_all(*([o["object_id"] for o in objects1] + [o["object_id"] for o in objects2]), 
                index= "object_id").order_by("size").pluck("object_id", "content", "size", "children").run()
            
            for content in content_cursor:
                if content["object_id"] in [o["object_id"] for o in objects1]: 
                    content1.append(content)
                if content["object_id"] in [o["object_id"] for o in objects2]:
                    content2.append(content)

            #print len(objects1), len(objects2), len(content1), len(content2)
            ids1, ids2 = {o["object_id"]: o["id"] for o in objects1}, {o["object_id"]: o["id"] for o in objects2}
            for i in xrange(len(content2)):
                if len(content1) <= i:
                    content_change_score = int(content2[i]["size"])
                    content_added_objects = [content2[i]["object_id"]]
                    content_added_objects_score = int(content2[i]["size"])
                else:
                    change = _object_compare(content1[i]["content"], content2[i]["content"])
                    content_added_objects = []
                    content_added_objects_score = 0
                    content_change_score = change

                change_score += content_change_score
                added_objects += content_added_objects
                added_objects_score += content_added_objects_score
                
                if save and ("children" not in content2[i] or len(content2[i]["children"]) == 0):
                    db.table("objects").get(ids2[content2[i]["object_id"]]).update({
                        "load_change": {
                            "change_score": content_change_score,
                            "new_files": content_added_objects,
                            "new_files_score": content_added_objects_score
                        }
                    }).run()

        #print guid, change_score, len(added_objects)
        return (change_score, added_objects, added_objects_score)
        pass

    def _compare_firmware(self, db, firmware1, firmware2, save= False):
        ### Query firmware objects
        if len(firmware1[2]) == 0 or len(firmware2[2]) == 0:
            print "Cannot compare versions (%d -> %d) without loaded firmware objects." % (firmware1[0], firmware2[0])
            return 

        ### This could be bad without guided-objects
        if len(firmware1[2]) != len(firmware2[2]):
            print "Firmware object count has changed between versions (%s -> %s)." % (firmware1[0], firmware2[0])

        change = self._compare_children(db, firmware1[2], firmware2[2], save= True)

        ### Save changes to update
        if save:
            db.table("updates").get_all(firmware2[1], index= "firmware_id").update({
                "load_change": {
                    "change_score": change[0],
                    "new_files": change[1],
                    "new_files_score": change[2],
                    "delta": firmware2[4] - firmware1[4]
                }
            }).run()
            db.table("objects").get_all(firmware2[1], index= "object_id").update({
                "load_change": {
                    "change_score": change[0],
                    "new_files": change[1],
                    "new_files_score": change[2],
                    "delta": firmware2[4] - firmware1[4]
                }
            }).run()
        print "Firmware %s change: %s" % (firmware2[1], str(change))
        pass

    def _load_meta(self, db, _object):
        content = base64.b64decode(_object["content"])
        entry = {
            "magic":  magic.from_buffer(content),
            "ssdeep": pydeep.hash_buf(content),
            "md5":    hashlib.md5(content).hexdigest(),
            "sha1":   hashlib.sha1(content).hexdigest(),
            "sha256": hashlib.sha256(content).hexdigest()
        }

        if entry["magic"] == "MS-DOS executable":
            ### This is a weak application of magic
            try: 
                pe_data = self._get_pe(content)
                for k, v in pe_data.iteritems(): entry[k] = v
            except Exception, e: print e; pass 
            pass
        #entry_copy = copy.deepcopy(entry)
        #del entry
        #del content
        #gc.collect()

        db.table("content").get(_object["id"]).update({"load_meta": entry}).run()
        print "Loaded meta for object (%s) %s." % (_object["firmware_id"], _object["id"])
        pass

    def _get_pe(self, content):
        def section_name(s): return s.Name.replace("\x00", "").strip()
        pe_entry = {}
        pe = pefile.PE(data= content)
        pe_entry["machine_type"] = pe.FILE_HEADER.Machine
        pe_entry["compile_time"] = pe.FILE_HEADER.TimeDateStamp
        pe_entry["sections"] = [section_name(s) for s in pe.sections if len(section_name(s)) > 0]
        pe_entry["linker"] = "%d,%d" % (pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion)
        pe_entry["os_version"] = "%d,%d" % (pe.OPTIONAL_HEADER.MajorOperatingSystemVersion, pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
        pe_entry["image_version"] = "%d,%d" % (pe.OPTIONAL_HEADER.MajorImageVersion, pe.OPTIONAL_HEADER.MinorImageVersion)
        pe_entry["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        pe_entry["subsystem_version"] = "%d,%d" % (pe.OPTIONAL_HEADER.MajorSubsystemVersion, pe.OPTIONAL_HEADER.MinorSubsystemVersion)
        del pe

        return pe_entry
        pass

    def _load_children(self, db, children):
        child_objects = db.table("objects").get_all(*children).pluck("id", "object_id", "load_meta", "children").run()
        for child in child_objects:
            if "children" in child and len(child["children"]) > 0:
                self._load_children(db, child["children"])
                continue

            contents = db.table("content").get_all(child["object_id"], index= "object_id").\
                filter(not r.row.contains("load_meta")).run()
            num = 0
            for content in contents:
                print "%d/??" % (num),
                num += 1
                self._load_meta(db, content)
                break
            del contents
        pass

    def _get_product_updates(self, db, product):
        updates = db.table("updates").order_by("date").filter(lambda update:
                update["products"].contains(product) & update.has_fields("firmware_id")
            ).map(r.row.merge({ "object_id": r.row["firmware_id"] })).eq_join("object_id", 
                db.table("objects"), index= "object_id"
            ).zip().run()
        return updates
        pass

    def command_load_meta(self, db, args):
        if args.vendor:
            vendor_products = []
            products = db.table("updates").order_by("date").filter(lambda update:
                update["vendor"].eq(args.vendor)
            ).pluck("products").run()
            for product_list in products:
                for product in product_list["products"]:
                    if product not in vendor_products:
                        vendor_products.append(product)
            products = vendor_products
            ### In an effort to avoid memory exhaustion
            for product in products:
                print "Recalling load_meta for product %s" % product
                subprocess.call("python %s load_meta --product \"%s\"" % (sys.argv[0], product), shell=True)
            return

        products = [args.product]

        for product in products:
            updates = self._get_product_updates(db, product)
            for update in updates:
                if "children" not in update or len(update["children"]) == 0:
                    continue
                self._load_children(db, update["children"])

    def command_load_change(self, db, args):
        if args.vendor:
            vendor_products = []
            products = db.table("updates").order_by("date").filter(lambda update:
                update["vendor"].eq(args.vendor)
            ).pluck("products").run()
            for product_list in products:
                for product in product_list["products"]:
                    if product not in vendor_products:
                        vendor_products.append(product)
            products = vendor_products
        else:
            products = [args.product]

        for product in products:
            updates = self._get_product_updates(db, product)
            firmware_objects = []

            for update in updates:
                firmware_objects.append((update["version"], update["firmware_id"], update["children"], "load_change" in update, update["date"]))

            for i in xrange(len(firmware_objects)-1):
                if not args.force and firmware_objects[i+1][3]:
                    print "Skipping change comparison (%s -> %s), already completed." % (firmware_objects[i][0], firmware_objects[i+1][0])
                    continue
                self._compare_firmware(db, firmware_objects[i], firmware_objects[i+1], True)

    def _add_lookup(self, db, guid, name, value, force= False):
        if db.table("objects").get_all(guid, index= "guid").is_empty().run():
            if force is False:
                print "Cannot find any files matching GUID (%s), please use the force option." % guid
                return
            pass

        if db.table("lookup").get_all(guid, index= "guid").is_empty().run():
            db.table("lookup").insert({
                "guid": guid,
                "%s" % name: value
            }).run()
            print "Added lookup for GUID (%s), with (%s) = (%s)." % (guid, name, value) 
        else:
            db.table("lookup").get_all(guid, index= "guid").update({"%s" % name: value}).run()
            print "Updated lookup for GUID (%s), set (%s) = (%s)." % (guid, name, value)
        pass       

    def command_add_lookup(self, db, args):
        self._add_lookup(db, args.guid, args.name, args.value, force= args.force)

    def command_load_guids(self, db, args):
        from uefi_firmware.guids import GUID_TABLES
        from uefi_firmware.utils import rfguid
        for table in GUID_TABLES:
            for name, r_guid in table.iteritems():
                #print name, rfguid(r_guid)
                self._add_lookup(db, rfguid(r_guid), "guid_name", name, True)
                pass

def parse_extra (parser, namespace):
    namespaces = []
    extra = namespace.extra
    while extra:
        n = parser.parse_args(extra)
        extra = n.extra
        namespaces.append(n)

    return namespaces

def main():

    argparser = argparse.ArgumentParser()
    subparsers = argparser.add_subparsers(help='Firmware Controls', dest='command')

    parser_list_fv = subparsers.add_parser("list_fv", help= "List all FV IDs which have files in the DB")

    parser_list_files = subparsers.add_parser("list_files", help= "List all files GUIDs for a given FV ID")
    parser_list_files.add_argument("fv_id",  help="Firmware ID.")

    '''Simple loading/parsing commands.'''
    parser_load_change = subparsers.add_parser("load_change", help= "Load change scores for objects and firmware.")
    parser_load_change.add_argument("-f", "--force", action="store_true", default= False, help="Force recalculation.")
    group = parser_load_change.add_mutually_exclusive_group(required= True)
    group.add_argument("--product", help="Product to load.")
    group.add_argument("--vendor", help="Vendor to load.")

    parser_load_meta = subparsers.add_parser("load_meta", help= "Extract meta, hashes for a machine's firmware.")
    parser_load_meta.add_argument("-f", "--force", action="store_true", default= False, help="Force recalculation.")
    group = parser_load_meta.add_mutually_exclusive_group(required= True)
    group.add_argument("--product", help="Product to load.")
    group.add_argument("--vendor", help="Vendor to load.")

    parser_add_lookup = subparsers.add_parser("add_lookup", help= "Add metadata about a file GUID.")
    parser_add_lookup.add_argument("-f", "--force", default=False, action= "store_true", help= "Force the lookup insert.")
    parser_add_lookup.add_argument("guid", help= "File GUID")
    parser_add_lookup.add_argument("name", help="Key to add to the GUID.")
    parser_add_lookup.add_argument("value", help= "Value")

    parser_load_guids = subparsers.add_parser("load_guids", help= "Read in EFI GUID definitions.")
    parser_load_guids.add_argument("-f", "--force", default= False, action= "store_true", help= "Override existing DB GUID definitions.")

    args = argparser.parse_args()

    controller = Controller()
    command = "command_%s" % args.command

    r.connect("localhost", 28015).repl()
    db = r.db("uefi")

    #objects_table = db.table("objects")
    #updates_table = db.table("updates")
    #content_table = db.table("content")
    #lookup_table = db.table("lookup")
    #stats_table = db.table("stats")

    command_ptr = getattr(controller, command, None)
    if command_ptr is not None:
        command_ptr(db, args)


if __name__ == '__main__':
    main()

