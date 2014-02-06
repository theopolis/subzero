import argparse, json, os, sys, time
import base64
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

    def command_compare_fv(self, db, args):
        files1 = db.table("uefi_files").filter({"firmware_id": args.fv_orig}).run()
        files2 = db.table("uefi_files").filter({"firmware_id": args.fv_new}).run()

        files_list1 = {_file["guid"]: _file for _file in files1}
        files_list2 = {_file["guid"]: _file for _file in files2}

        for guid, _file in files_list1.iteritems():
            if guid not in files_list2:
                print "%s (%s) not in %s" % (guid, _file["name"], args.fv_new) #,show_file(value)
        for guid, _file in files_list2.iteritems():
            if guid not in files_list1:
                print "%s (%s) not in %s" % (guid, _file["name"], args.fv_orig) #,show_file(value)

        difference_count = 0
        for guid, _file in files_list1.iteritems():
            if guid not in files_list2: continue
            if file_compare(guid, _file, files_list2[guid]):
                difference_count += 1
        print "%d files, %d different files" % (len(files_list1), difference_count)

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
        #if "attrs" in _object and "type_name" in _object["attrs"]:
        #    name = "%s-%s" % (name, _object["attrs"]["type_name"])
        #    _dump_data("%s.obj" % name, base64.b64decode(_object["content"]))
        #if "objects" in _object:
        #    for _obj in _object["objects"]: self._dump_objects(name, _obj)
        #pass
        if "attrs" in _object and "type_name" in _object["attrs"]:
            name = "%s-%s" % (name, _object["attrs"]["type_name"])
        _dump_data("%s.obj" % name, base64.b64decode(_object["content"]))


    def command_dump_file(self, db, args):
        files = db.table("files").filter({"firmware_id": args.fv_id, "guid": args.guid}).limit(1).run()
        children = db.table("objects").filter({"firmware_id": args.fv_id, "guid": args.guid}).run()
        for _object in children:
            self._dump_objects(args.guid, _object)

    def command_dump_files(self, db, args):
        files = db.table("uefi_files").filter({"guid": args.guid}).run()
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
        files = db.table("uefi_files").filter({"firmware_id": args.fv_id}).run()
        for _file in files:
            if _file["type"] not in [2, 1]: continue
            self._dump_objects(_file["guid"], _file)
        pass

    def command_search_string(self, db, args):
        if args.fvid:
            files = db.table("uefi_files").filter({"firmware_id": args.fvid}).pluck("strings", "firmware_id", "guid", "name").run()
        else:
            files = db.table("uefi_files").pluck("strings", "firmware_id", "guid", "name").run()
        for _file in files:
            for _string in _file["strings"]:
                if _string.lower().find(args.search.lower()) >= 0:
                    print "%s-%s (%s) %s" % (_file["firmware_id"], _file["guid"], _file["name"], _string)

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

    parser_search_string = subparsers.add_parser("search_string", help= "Search for a string")
    parser_search_string.add_argument("--fvid", help="Limit searching to firmware ID.")
    parser_search_string.add_argument("search", help="String to search")

    parser_compare_fv = subparsers.add_parser("compare_fv", help= "Compare two firmware updates and display stats.")
    parser_compare_fv.add_argument("fv_orig", help="Original firmware ID")
    parser_compare_fv.add_argument("fv_new", help="New firmware ID")

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

