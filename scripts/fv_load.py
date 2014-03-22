import argparse
import hashlib
import pefile
import os
import base64
import copy
import sys

import rethinkdb as r

from uefi_firmware import *
from uefi_firmware.pfs import PFSFile

def brute_search(data):
    volumes = utils.search_firmware_volumes(data)
    objects = []

    for index in volumes:
        objects += parse_firmware_volume(data[index-40:], name=index)
    return objects
    pass

def parse_firmware_volume(data, name="volume"):
    firmware_volume = uefi.FirmwareVolume(data, name)
    firmware_volume.process()

    objects = firmware_volume.iterate_objects(True)
    return objects

def get_file_name(_object):
    if len(_object["label"]) > 0:
        return _object["label"]
    if not "objects" in _object:
        return None
    for _sub_object in _object["objects"]:
        if not isinstance(_sub_object["_self"], uefi.EfiSection):
            continue
        name = get_file_name(_sub_object)
        if name is not None:
            return name
    return None

def get_file_description(_object):
    if isinstance(_object["_self"], uefi.FreeformGuidSection):
        return _object["label"]
    if "objects" not in _object:
        return None
    for _sub_object in _object["objects"]:
        if not isinstance(_sub_object["_self"], uefi.EfiSection):
            continue
        description = get_file_description(_sub_object)
        if description is not None:
            return description
    return None 

def get_files(objects):
    files = {}
    for _object in objects:
        if _object["type"] == "FirmwareFile":
            files[_object["guid"]] = {
                "name": get_file_name(_object), 
                "description": get_file_description(_object),
                "attrs": _object["attrs"],
                "objects": _object["objects"],
                "content": _object["content"],
                "guid": _object["guid"]
            }
        if "objects" in _object:
            for key, value in get_files(_object["objects"]).iteritems():
                files[key] = value
    return files

def _strings(_object, min=10):
    import string
    result = ""
    for c in _object["content"]:
        if c == 0x00: continue
        if c in string.printable:
            result += c
            continue
        if len(result.strip()) >= min:
            yield result
        result = ""

def _load_pe(_object):
    _types = {267: "x86", 523: "x86_64"}

    pe_object = _find_pe(_object)
    if pe_object is None: 
        return None

    pe_info = {}

    pe_info["sections"] = {}
    pe = pefile.PE(data= pe_object["content"])

    pe_info["machine_type"] = pe.FILE_HEADER.Machine
    pe_info["compile_time"] = pe.FILE_HEADER.TimeDateStamp
    pe_info["subsystem"] = pe.OPTIONAL_HEADER.Subsystem

    for section in pe.sections:
        #pe_1_sections[section.Name.replace("\x00", "")] = section
        pe_info["sections"][section.Name.replace("\x00", "")] = base64.b64encode(section.get_data(0))
        pe_info["sections"][section.Name.replace("\x00", "") + "_md5"] = hashlib.md5(section.get_data(0)).hexdigest()

def _object_entry(_object):
    return {key: value for key, value in _object.iteritems() if key in ["guid", "type", "attrs", "object_id", "chunks", "other"]}

def store_object(firmware_id, _object):
    if "_self" in _object:
        ### If this is an EFI object, it must be a basic object (section object)
        if isinstance(_object["_self"], uefi.FirmwareObject) and not isinstance(_object["_self"], uefi.EfiSection): 
            return None

    '''Store base objects only.'''
    if "objects" not in _object or len(_object["objects"]) == 0:
        entry = _object_entry(_object)
        entry["firmware_id"] = firmware_id
        entry["content"] = base64.b64encode(_object["content"])
   
        result = db.table("objects").insert(entry).run()
        key = result["generated_keys"][0]

        return [key]

    children = []
    for _sub_object in _object["objects"]:
        key = store_object(firmware_id, _sub_object)
        if key is not None:
            children += key
    return children

def store_file(firmware_id, file):
    entry = _object_entry(file)

    if not db.table("files").get_all(firmware_id, index="firmware_id").filter({"guid": file["guid"]}).is_empty().run():
        '''If the file already exists for this GUID/FirmwareID pair, skip.'''
        print "Skipping file (%s) guid (%s), already exists." % (fimrware_id, file["guid"])
        return

    children = []
    for _object in file["objects"]:
        children += store_object(firmware_id, _object)
    #print children

    if len(children) == 0:
        print "Storing a cloned child for (%s)." % file["guid"]
        entry["no_children"] = True
        children += store_object(firmware_id, file)

    entry["children"] = children
    entry["firmware_id"] = firmware_id
    entry["content"] = base64.b64encode(file["content"])
    entry["name"] = file["name"]
    entry["description"] = file["description"]

    db.table("files").insert(entry).run()
    print "Stored UEFI file (%s) %s." % (firmware_id, file["guid"])

def load_uefi_volumes(firmware_id, data):
    objects = brute_search(data)

    files = get_files(objects)
    for key in files:
        store_file(firmware_id, files[key])
    pass

def load_capsule(firmware_id, data):
    capsule = uefi.FirmwareCapsule(data)
    if not capsule.valid_header:
        print "This is not a valid UEFI firmware capsule."
        sys.exit(1)
    
    capsule.process()
    ### Todo: insert Capsule information

    volume = capsule.capsule_body
    volume_info = volume.info(include_content= True)
    if not db.table("objects").get_all(firmware_id, index="firmware_id").filter({"guid": volume_info["guid"]}).is_empty().run():
        print "Skipping GUID %s, object exists." % volume_info["guid"]
        return

    volume_id = get_firmware_id(volume_info["content"])
    objects = volume.iterate_objects(True)
    files = get_files(objects)
    for key in files:
        store_file(firmware_id, files[key])

def load_pfs(firmware_id, data):
    pfs = PFSFile(data)
    if not pfs.check_header():
        print "This is not a valid DELL PFS update."
        sys.exit(1)

    pfs.process()
    for section in pfs.objects:
        section_info = section.info(include_content= True)

        if not db.table("objects").get_all(firmware_id, index="firmware_id").filter({"guid": section_info["guid"]}).is_empty().run():
            print "Skipping GUID %s, object exists." % section_info["guid"]
            continue

        section_id = get_firmware_id(section_info["content"])
        section_info["object_id"] = section_id
        section_info["chunks"] = [base64.b64encode(chunk) for chunk in section_info["chunks"]]

        store_object(firmware_id, section_info)
        print "Stored PFS object (%s) %s." % (firmware_id, section_info["guid"])

        load_uefi_volumes(section_id, section_info["content"])
    pass

def set_update(firmware_id, data, label_type, item_id= None):
    ### Set the label for the item
    if item_id is not None:
        db.table("updates").get_all(item_id, index="item_id").update({
            "firmware_id": firmware_id,
            "type": label_type
        }).run()
        print "Updating update %s to firmware ID: %s (%s)." % (item_id, firmware_id, label_type)

    if not db.table("updates").get_all(firmware_id, index="firmware_id").is_empty().run():
        ### Add size of the firmware to the updates table
        db.table("updates").get_all(firmware_id, index="firmware_id").update({
            "size": len(data)
        }).run()
        print "Updating size for firmware ID: %s (%s)." % (firmware_id, label_type)
    pass

def get_firmware_id(data):
    return hashlib.md5(data).hexdigest()

ITEM_TYPES = {
    "capsule": "uefi_capsule",
    "pfs": "dell_pfs",
    "me": "intel_me",
    "bios": "bios_rom",
    "uefi": "firmware_volume"
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pfs", action="store_true", default=False, help="This is a DELL PFS update.")
    parser.add_argument("--bios", action="store_true", default=False, help="This is a BIOS ROM.")
    parser.add_argument("--me", action="store_true", default=False, help="This is an Intel ME container.")
    parser.add_argument("--capsule", action= "store_true", default= False, help= "This is a UEFI firmware capsule.")
    parser.add_argument("-i", "--item", default= None, help= "Set the update with this item_id to the firmware_id.")
    parser.add_argument("file", help="The file to work on")

    args = parser.parse_args()

    try:
        with open(args.file, 'rb') as fh: input_data = fh.read()
    except Exception, e:
        print "Error: Cannot read file (%s) (%s)." % (args.file, str(e))
        sys.exit(1)

    firmware_id = get_firmware_id(input_data)
    
    r.connect("localhost", 28015).repl()
    db = r.db("uefi")

    label_type = "unknown"
    if args.pfs: label_type = ITEM_TYPES["pfs"]
    elif args.bios: label_type = ITEM_TYPES["bios"]
    elif args.me: label_type = ITEM_TYPES["me"]
    elif args.capsule: label_type = ITEM_TYPES["capsule"]
    else: label_type = ITEM_TYPES["firmware_volume"]

    set_update(firmware_id, input_data, label_type, item_id= args.item)

    if args.pfs:
        load_pfs(firmware_id, input_data)
    elif args.capsule:
        load_capsule(firmware_id, input_data)
    else:
        load_uefi_volumes(firmware_id, input_data)



