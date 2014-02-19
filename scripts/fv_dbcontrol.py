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

def _file_compare(db, file1, file2):
    md5_1 = hashlib.md5(file1["content"]).hexdigest()
    md5_2 = hashlib.md5(file2["content"]).hexdigest()
    
    if md5_1 == md5_2: return 0

    objects1 = db.table("objects").filter({"guid": file1["guid"], "firmware_id": file1["firmware_id"]}).order_by(r.row["attrs"]["size"]).run()
    objects1 = [obj for obj in objects1]
    objects2 = db.table("objects").filter({"guid": file2["guid"], "firmware_id": file2["firmware_id"]}).order_by(r.row["attrs"]["size"]).run()
    objects2 = [obj for obj in objects2]

    change_score = 0
    for i in xrange(len(objects1)):
        change_score += _object_compare(objects1[i]["content"], objects2[i]["content"])

    return change_score
    pass

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

    def _compare_fv(self, db, fvid1, fvid2, save= False):
        files1 = db.table("files").filter({"firmware_id": fvid1}).run()
        files2 = db.table("files").filter({"firmware_id": fvid2}).run()

        files_list1 = {_file["guid"]: _file for _file in files1}
        files_list2 = {_file["guid"]: _file for _file in files2}

        if len(files_list1) == 0 or len(files_list2) == 0:
            print "Cannot compare volumes (%s -> %s) without loaded firmware." % (fvid1, fvid2)
            return 0

        change_score = 0
        new_files = []
        new_files_score = 0
        for guid, _file in files_list1.iteritems():
            if guid not in files_list2:
                print "%s (%s) not in %s" % (guid, _file["name"], fvid1)
                change_score += files_list1[guid]["attrs"]["size"]
                pass
        for guid, _file in files_list2.iteritems():
            if guid not in files_list1:
                print "%s (%s) not in %s" % (guid, _file["name"], fvid2)
                change_score += files_list2[guid]["attrs"]["size"]
                new_files.append(guid)
                new_files_score += files_list2[guid]["attrs"]["size"]

                if save:
                    db.table("files").filter({"firmware_id": fvid2, "guid": guid}).update(
                        {"load_change": {"new_file": True}}
                    ).run()
                    print "New file (%s) %s." % (fvid2, guid)
                pass

        for guid, _file in files_list1.iteritems():
            if guid not in files_list2: continue
            score = _file_compare(db, _file, files_list2[guid])
            if score == 0: continue

            db.table("files").filter({"firmware_id": fvid2, "guid": guid}).update(
                {"load_change": {"change_score": score}
            }).run()
            print "Loaded change for file (%s) %s of %d." % (fvid2, guid, score)

            change_score += score

        return {"change_score": change_score, "new_files": new_files, "new_files_score": new_files_score}
        pass

    def _compare_firmware(self, db, firmware1, firmware2, save= False):
        ### Query firmware objects
        if len(firmware1[2]) == 0 or len(firmware2[2]) == 0:
            print "Cannot compare versions (%d -> %d) without loaded firmware." % (firmware1[0], firmware2[0])
            return 

        firmware_change_score = 0
        firmware_added_objects = []
        firmware_added_objects_score = 0
        if len(firmware1[2]) != len(firmware2[2]):
            print "Firmware object count has changed between versions (%d -> %d)." % (firmware1[0], firmware2[0])

        firmware_change_score = 0
        for guid in firmware2[2].keys():
            object_change_score = 0
            if guid in firmware1[2] and firmware1[2][guid] == firmware2[2][guid]:
                ### Objects are indexed by their hash
                continue

            ### Check if this is a new object
            if guid not in firmware2[2]:
                firmware_added_objects += 1

                object1 = db.table("objects").filter({"object_id": firmware2[2][guid]}).pluck("content").run()
                object1 = [_obj["content"] for _obj in object1][0]
                firmware_added_objects.append((firmware1[2][guid], ""))
                firmware_added_objects_score += object1["attrs"]["size"]
                object_change_score = object1["attrs"]["size"]

            ### Apply some check if to determine if the object was a set of firmware volumes
            elif not db.table("files").filter({"firmware_id": firmware1[2][guid]}).is_empty().run():
                #print "Would compare FV for %s." % guid
                #continue
                changes = self._compare_fv(db, firmware1[2][guid], firmware2[2][guid], True)
                db.table("objects").filter({"object_id": firmware2[2][guid]}).update({
                    "load_change": changes
                }).run()

                if "new_files" in changes:
                    firmware_added_objects += [(firmware1[2][guid], _file) for _file in changes["new_files"]]
                    firmware_added_objects_score += changes["new_files_score"]
                object_change_score = changes["change_score"]
            ### Apple some check to determine if ME

            ### Compare objects directly
            else:
                object1 = db.table("objects").filter({"object_id": firmware1[2][guid]}).pluck("content").run()
                object1 = [_obj["content"] for _obj in object1][0]

                object2 = db.table("objects").filter({"object_id": firmware2[2][guid]}).pluck("content").run()
                object2 = [_obj["content"] for _obj in object2][0]

                object_change_score = _object_compare(object1, object2)
                db.table("objects").filter({"object_id": firmware2[2][guid]}).update({
                    "load_change": {"change_score": object_change_score}
                }).run()

            firmware_change_score += object_change_score
            print "Object %s change: %d." % (guid, object_change_score)

        ### Save changes to update
        db.table("updates").filter({"firmware_id": firmware2[1]}).update({
            "load_change": {
                "change_score": firmware_change_score,
                "new_files": firmware_added_objects,
                "new_files_score": firmware_added_objects_score
            }
        }).run()
        print "Firmware %s change: %d" % (firmware2[1], firmware_change_score)
        pass

    def command_load_change(self, db, args):
        updates = db.table("updates").filter({"machine": args.machine}).order_by("version").\
            pluck("version", "firmware_id", "type", "load_change").run()
        firmware_objects = []

        for update in updates:
            objects = db.table("objects").filter({"firmware_id": update["firmware_id"]}).\
            pluck("object_id", "guid").run()
            objects = {_obj["guid"]:_obj["object_id"] for _obj in objects}
            firmware_objects.append((update["version"], update["firmware_id"], objects, "load_change" in update))

        for i in xrange(len(firmware_objects)-1):
            if not args.force and firmware_objects[i+1][3]:
                print "Skipping change comparison (%d -> %d), already completed." % (firmware_objects[i][0], firmware_objects[i+1][0])
                continue
            self._compare_firmware(db, firmware_objects[i], firmware_objects[i+1], True)

    def _load_meta(self, db, _object):
        content = base64.b64decode(_object["content"])
        #print _object["firmware_id"]
        db.table("objects").filter({"id": _object["id"]}).update({
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

    def command_load_meta(self, db, args):
        def load_objects(firmware_id):
            objects = db.table("objects").filter({"firmware_id": firmware_id})\
                .pluck("firmware_id", "id", "object_id", "content").run()
            for _object in objects:
                self._load_meta(db, _object)
                if "object_id" in _object.keys():
                    load_objects(_object["object_id"])
            
        fobjects = db.table("updates").filter({"machine": args.machine}).order_by("version").\
            pluck("version", "firmware_id", "load_meta").run()
        for _object in fobjects:
            if not args.force and "load_meta" in _object:
                print "Skipping parsing of (%s), already completed." % _object["firmware_id"]
                continue
            load_objects(_object["firmware_id"])

    def _dump_pe(self, _object):
        def _get_pes(_object):
            pes = []
            if "objects" in _object.keys():
                for _obj in _object["objects"]: pes += _get_pes(_obj)
            #print _object["type_name"]
            if "attrs" in _object.keys() and _object["attrs"]["type"] in [16]:
                pes.append(_object["content"])
            return pes
            pass

        pes = _get_pes(_object)
        for i, _pe in enumerate(pes):
            _dump_data("%s-%s.pe32" % (_object["guid"], _object["name"]), base64.b64decode(_pe))
        pass

    def command_dump_pe(self, db, args):
        files = db.table("uefi_files").filter({"firmware_id": args.fv_id, "guid": args.guid}).limit(1).run()

        for _file in files:
            _object = _file
            break

        self._dump_pe(_object)
    pass

    def command_dump_pes(self, db, args):
        files = db.table("uefi_files").filter({"firmware_id": args.fv_id}).run()
        for _file in files:
            self._dump_pe(_file)

    def _dump_objects(self, name, _object):
        if "attrs" in _object and "type_name" in _object["attrs"]:
            name = "%s-%s" % (name, _object["attrs"]["type_name"])
        _dump_data("%s.obj" % name, base64.b64decode(_object["content"]))


    def command_dump_file(self, db, args):
        files = db.table("files").filter({"firmware_id": args.fv_id, "guid": args.guid}).limit(1).run()
        children = db.table("objects").filter({"firmware_id": args.fv_id, "guid": args.guid}).run()
        for _object in children:
            self._dump_objects(args.guid, _object)

    def command_dump_files(self, db, args):
        files = db.table("files").filter({"guid": args.guid}).run()
        files = {_file["firmware_id"]: _file for _file in files}

        if args.machine:
            fvs = db.table("updates").filter({"machine": args.machine}).pluck("version", "firmware_id").run()
            for _fv in fvs:
                self._dump_objects("%d-%s" % (_fv["version"], args.guid), files[_fv["firmware_id"]])
        else:
            for _file in files:
                self._dump_objects("%s-%s" % (_file["firmware_id"], args.guid), _file)
        pass

    def command_dump_others(self, db, args):
        files = db.table("files").filter({"firmware_id": args.fv_id}).run()
        for _file in files:
            if _file["attrs"]["type"] not in [2, 1]: continue
            self._dump_objects(_file["guid"], _file)
        pass

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
    subparsers = argparser.add_subparsers(help='FV Controls', dest='command')

    parser_list_fv = subparsers.add_parser("list_fv", help= "List all FV IDs which have files in the DB")

    parser_list_files = subparsers.add_parser("list_files", help= "List all files GUIDs for a given FV ID")
    parser_list_files.add_argument("fv_id",  help="Firmware ID.")

    #parser_dump_pe = subparsers.add_parser("dump_pe", help= "Write PE object if it exists.")
    #parser_dump_pe.add_argument("fv_id", help="Firmware ID.")
    #parser_dump_pe.add_argument("guid", help="File GUID.")

    #parser_dump_pes = subparsers.add_parser("dump_pes", help= "Write all PEs from a given firmware ID.")
    #parser_dump_pes.add_argument("fv_id", help="Firmware ID.")

    parser_dump_file = subparsers.add_parser("dump_file", help= "Write file objects.")
    parser_dump_file.add_argument("fv_id", help="Firmware ID.")
    parser_dump_file.add_argument("guid", help="File GUID.")

    parser_dump_files = subparsers.add_parser("dump_files", help= "Write a file from every fv")
    parser_dump_files.add_argument("--machine", help="Limit files to a specific machine")
    parser_dump_files.add_argument("guid", help="File to dump")

    parser_dump_others = subparsers.add_parser("dump_others", help= "Dump files that are not drivers/PEs")
    parser_dump_others.add_argument("fv_id", help="Firmware ID.")

    '''Simple loading/parsing commands.'''
    parser_load_change = subparsers.add_parser("load_change", help= "Load change scores for files and firmware.")
    parser_load_change.add_argument("machine", help="Machine name to load.")
    parser_load_change.add_argument("-f", "--force", action="store_true", default= False, help="Force recalculation.")

    parser_load_meta = subparsers.add_parser("load_meta", help= "Extract meta, hashes for a machine's firmware.")
    parser_load_meta.add_argument("machine", help= "Machien name to load.")
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

