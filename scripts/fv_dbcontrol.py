import argparse, json, os, sys, time
import base64

import hashlib
import pydeep
import magic

import rethinkdb as r

from utils import red

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
        children1 = {}
        children2 = {}
        child_cursor = db.table("objects").get_all(*(list1 + list2)).pluck("id", "size", "object_id", "guid", "children").run()

        for i, child in enumerate(child_cursor):
            if "guid" not in child:
                child["guid"] = i
            if child["id"] in list1:
                if child["guid"] not in children1: children1[child["guid"]] = []
                children1[child["guid"]].append(child)
            else: 
                if child["guid"] not in children2: children2[child["guid"]] = []
                children2[child["guid"]].append(child)

        objects1 = []
        objects2 = []
        for guid in children2.keys():
            if guid not in children1:
                ### This guid/object was added in the update
                added_objects += [c["object_id"] for c in children2[guid]]
                added_objects_score += sum([int(c["size"]) for c in children2[guid]])
                ### Todo: this does not account for nested children in a new update
                continue
            for i in xrange(len(children2[guid])):
                if "children" in children2[guid][i] and len(children2[guid][i]["children"]) > 0:
                    ### There are nested children, compare them individually.
                    #print "comparing children"
                    nested_change = self._compare_children(db, children1[guid][i]["children"], children2[guid][i]["children"], save= save)
                    #print "finished"
                    change_score += nested_change[0]
                    added_objects += nested_change[1]
                    added_objects_score += nested_change[2]

                    if save:
                        #print children2[guid][i]["id"]
                        db.table("objects").get(children2[guid][i]["id"]).update({
                            "load_change": {
                                "change_score": nested_change[0],
                                "new_files": nested_change[1],
                                "new_files_score": nested_change[2]
                            }
                        }).run()

                    continue
                #if children1[guid][i]["object_id"] == children2[guid][i]["object_id"]:
                #    continue
                objects1.append(children1[guid][i]["object_id"])
                objects2.append(children2[guid][i]["object_id"])

        ### If there are objects, compare the content
        content1 = []
        content2 = []
        content_cursor = db.table("content").get_all(*(objects1 + objects2), 
            index= "object_id").order_by("size").pluck("object_id", "content", "size").run()
        
        for content in content_cursor:
            if content["object_id"] in objects1: 
                content1.append(content)
            if content["object_id"] in objects2:
                content2.append(content)

        for i in xrange(len(content2)):
            change = _object_compare(content1[i]["content"], content2[i]["content"])
            #print content1[i]["size"], content2[i]["size"], change
            change_score += change

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
                    "new_files_score": change[2]
                }
            }).run()
            db.table("objects").get_all(firmware2[1], index= "object_id").update({
                "load_change": {
                    "change_score": change[0],
                    "new_files": change[1],
                    "new_files_score": change[2]
                }
            }).run()
        print "Firmware %s change: %s" % (firmware2[1], str(change))
        pass

    def _load_meta(self, db, _object):
        content = base64.b64decode(_object["content"])
        #print _object["firmware_id"]
        db.table("objects").get(_object["id"]).update({
            "load_meta": {
                "magic":  magic.from_buffer(content),
                "ssdeep": pydeep.hash_buf(content),
                "md5":    hashlib.md5(content).hexdigest(),
                "sha1":   hashlib.sha1(content).hexdigest(),
                "sha256": hashlib.sha256(content).hexdigest()
            }
        }).run()
        print "Loaded meta for object (%s) %s." % (_object["firmware_id"], _object["id"])
        pass

    def _load_children(self, db, children):
        child_objects = db.table("objects").get_all(*children).pluck("id", "object_id", "load_meta", "children").run()
        for child in child_objects:
            if "children" in child and len(child["children"]) > 0:
                #for child_key in child_object["children"]:
                self._load_children(db, child["children"])
                continue

            contents = db.table("content").get_all(child["object_id"], index= "object_id").run()
            for content in contents:
                self._load_meta(db, content)
                break
        pass

    def _get_product_updates(self, db, product):
        updates = db.table("updates").order_by("date").filter(lambda update:
                update["products"].contains(product)
            ).map(r.row.merge({ "object_id": r.row["firmware_id"] })).eq_join("object_id", 
                db.table("objects"), index= "object_id"
            ).zip().run()
        return updates
        pass

    def command_load_meta(self, db, args):
        updates = self._get_product_updates(db, args.product)
        for update in updates:
            if "children" not in update or len(update["children"]) == 0:
                continue
            self._load_children(db, update["children"])

    def command_load_change(self, db, args):
        updates = self._get_product_updates(db, args.product)
        firmware_objects = []

        for update in updates:
            firmware_objects.append((update["version"], update["firmware_id"], update["children"], "load_change" in update))

        for i in xrange(len(firmware_objects)-1):
            if not args.force and firmware_objects[i+1][3]:
                print "Skipping change comparison (%s -> %s), already completed." % (firmware_objects[i][0], firmware_objects[i+1][0])
                continue
            self._compare_firmware(db, firmware_objects[i], firmware_objects[i+1], True)

    def command_add_lookup(self, db, args):
        if db.table("files").filter({"guid": args.guid}).is_empty().run():
            if args.force is False:
                print "Cannot find any files matching GUID (%s), please use the force option." % args.guid
                return

        if db.table("lookup").filter({"guid": args.guid}).is_empty().run():
            db.table("lookup").insert({
                "guid": args.guid,
                "%s" % args.name: args.value
            }).run()
            print "Added lookup for GUID (%s), with (%s) = (%s)." % (args.guid, args.name, args.value) 
        else:
            db.table("lookup").filter({"guid": args.guid}).update({"%s" % args.name: args.value}).run()
            print "Updated lookup for GUID (%s), set (%s) = (%s)." % (args.guid, args.name, args.value)
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
    parser_load_change.add_argument("product", help="Product to load.")
    parser_load_change.add_argument("-f", "--force", action="store_true", default= False, help="Force recalculation.")

    parser_load_meta = subparsers.add_parser("load_meta", help= "Extract meta, hashes for a machine's firmware.")
    parser_load_meta.add_argument("product", help= "Product to load.")
    parser_load_meta.add_argument("-f", "--force", action="store_true", default= False, help="Force recalculation.")

    parser_add_lookup = subparsers.add_parser("add_lookup", help= "Add metadata about a file GUID.")
    parser_add_lookup.add_argument("guid", help= "File GUID")
    parser_add_lookup.add_argument("name", help="Key to add to the GUID.")
    parser_add_lookup.add_argument("value", help= "Value")
    parser_add_lookup.add_argument("-f", "--force", default=False, action= "store_true", help= "Force the lookup insert.")

    args = argparser.parse_args()

    controller = Controller()
    command = "command_%s" % args.command

    r.connect("localhost", 28015).repl()
    db = r.db("uefi")

    command_ptr = getattr(controller, command, None)
    if command_ptr is not None:
        command_ptr(db, args)


if __name__ == '__main__':
    main()

