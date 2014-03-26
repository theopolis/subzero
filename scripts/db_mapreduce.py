import argparse, json, os, sys, time
import rethinkdb as r

class Controller(object):
    def command_guid_group(self, db, args):
        db.table("stats").get_all("uefi_guid", index= "type").delete().run()
        return db.table("objects").group_by("guid", r.count).with_fields("reduction", {"group": "guid"}).map(lambda guid:
            {
                "key": guid["group"]["guid"], 
                "date": r.now().to_epoch_time(), 
                "type": "uefi_guid", 
                "result": guid["reduction"]
            }
        )
        pass

    def command_object_group(self, db, args):
        db.table("stats").get_all("object_id", index= "type").delete().run()
        return db.table("objects").group_by("object_id", r.count).with_fields("reduction", {"group": "object_id"}).map(lambda guid:
            {
                "key": guid["group"]["object_id"], 
                "date": r.now().to_epoch_time(), 
                "type": "object_id", 
                "result": guid["reduction"]
            }
        )
        pass

    def command_vendor_object_sum(self, db, args):
        db.table("stats").get_all("vendor_object_size", index= "type").delete().run()
        return db.table("objects").group_by("vendor", r.sum("size")).with_fields("reduction", {"group": "vendor"}).map(lambda guid:
            {
                "key": guid["group"]["vendor"], 
                "date": r.now().to_epoch_time(), 
                "type": "vendor_object_size", 
                "result": guid["reduction"]
            }
        )

    def command_vendor_content_sum(self, db, args):
        db.table("stats").get_all("vendor_content_size", index= "type").delete().run()
        return db.table("content").group_by("vendor", r.sum("size")).with_fields("reduction", {"group": "vendor"}).map(lambda guid:
            {
                "key": guid["group"]["vendor"], 
                "date": r.now().to_epoch_time(), 
                "type": "vendor_content_size", 
                "result": guid["reduction"]
            }
        )

def main():

    argparser = argparse.ArgumentParser()
    subparsers = argparser.add_subparsers(help='Firmware MapReduce Controls', dest='command')

    parser_guid_group = subparsers.add_parser("guid_group", help= "Groupby UEFI file GUIDs.")
    parser_object_group = subparsers.add_parser("object_group", help= "Groupby Object hashs.")
    parser_vendor_object_sum = subparsers.add_parser("vendor_object_sum", help= "Sum objects by vendor.")
    parser_vendor_content_sum = subparsers.add_parser("vendor_content_sum", help= "Sum content by vendor.")

    args = argparser.parse_args()
    controller = Controller()
    command = "command_%s" % args.command

    r.connect("localhost", 28015).repl()
    db = r.db("uefi")

    command_ptr = getattr(controller, command, None)
    if command_ptr is not None:
        print "Running command (%s)..." % args.command
        begin = time.time()
        db.table("stats").insert(command_ptr(db, args).limit(99999)).run()
        end = time.time()
        print "...finished (%d) seconds." % (end-begin)

if __name__ == '__main__':
    main()