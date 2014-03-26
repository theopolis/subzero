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

#def brute_search(data):
#    volumes = utils.search_firmware_volumes(data)
#    objects = []
#
#    for index in volumes:
#        objects += parse_firmware_volume(data[index-40:], name=index)
#    return objects
#    pass

#def parse_firmware_volume(data, name="volume"):
#    firmware_volume = uefi.FirmwareVolume(data, name)
#    firmware_volume.process()
#
#    objects = firmware_volume.iterate_objects(True)
#    return objects

#def load_uefi_volumes(firmware_id, data):
#    objects = brute_search(data)
#
#    files = get_files(objects)
#    for uefi_file in files:
#        store_file(firmware_id, uefi_file)
#    pass

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
    ### They may be duplicate file-GUIDs in a volume/capsule/etc.
    #files = {}
    files = []
    for _object in objects:
        if _object["type"] == "FirmwareFile":
            #files[_object["guid"]] = {
            files.append({
                #"name": get_file_name(_object), 
                #"description": get_file_description(_object),
                "attrs": dict(_object["attrs"].items() + {
                    "name": get_file_name(_object),
                    "description": get_file_description(_object),
                    }.items()
                ),
                "objects": _object["objects"],
                "content": _object["content"],
                "guid": _object["guid"]
            })
        if "objects" in _object:
            for uefi_file in get_files(_object["objects"]):
                files.append(uefi_file)
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
    #return {key: value for key, value in _object.iteritems() if key in ["guid", "type", "attrs", "object_id", "chunks", "other"]}
    entry = {k: v for k, v in _object.iteritems() if k in ["guid", "type", "attrs", "chunks", "other"]}
    return entry

def store_content(firmware_id, object_id, content, content_type= "object"):
    if not content_table.get_all(object_id, index="object_id").is_empty().run():
        '''If the content entry already exists for this object_id (hash), skip inserting content.'''
        print "Skipping object content (%s) (%s), already exists." % (firmware_id, object_id)
        return
    content_table.insert({
        "firmware_id": firmware_id,
        "object_id": object_id,
        "type": content_type,
        "size": len(content),
        "content": base64.b64encode(content)
    }).run()

def store_object(firmware_id, _object, object_type= "uefi_object"):
    if "_self" in _object:
        ### If this is an EFI object, it must be a basic object (section object)
        if isinstance(_object["_self"], uefi.FirmwareObject) and not isinstance(_object["_self"], uefi.EfiSection): 
            return None

    '''Store base objects only.'''
    object_id = get_firmware_id(_object["content"])
    if "objects" not in _object or len(_object["objects"]) == 0:
        entry = _object_entry(_object)
        entry["firmware_id"] = firmware_id
        entry["object_id"] = object_id

        entry["size"] = len(_object["content"])
        entry["type"] = object_type
        #entry["content"] = base64.b64encode(_object["content"])

        ### Store object content
        store_content(firmware_id, object_id, _object["content"])
   
        ### Store this entry
        keys = get_result_keys(objects_table.insert(entry).run())
        return keys

    children = []
    for _sub_object in _object["objects"]:
        key = store_object(firmware_id, _sub_object)
        if key is not None:
            children += key
    return children

def store_file(firmware_id, uefi_file):
    entry = _object_entry(uefi_file)

    ### Used to store the file content
    file_id = get_firmware_id(uefi_file["content"])
    ### Do not store file content (yet), may be too much data

    children = []
    for _object in uefi_file["objects"]:
        children += store_object(firmware_id, _object)
    #print children

    if len(children) == 0:
        print "Storing a base UEFI file/object for GUID (%s)." % uefi_file["guid"]
        entry["no_children"] = True
        store_content(firmware_id, file_id, uefi_file["content"])
        #if object_keys is not None: 
        #children += object_keys
        #return object_keys

    entry["children"] = children
    entry["firmware_id"] = firmware_id
    entry["object_id"] = file_id

    entry["size"] = len(uefi_file["content"])
    entry["type"] = "uefi_file"

    ### Additional (and optional) UEFI file-only attributes
    entry["attrs"] = uefi_file["attrs"]
    #entry["attrs"]["name"] = uefi_file["name"]
    #entry["attrs"]["description"] = uefi_file["description"]

    keys = get_result_keys(objects_table.insert(entry).run())
    print "Stored UEFI file (%s) %s." % (firmware_id, uefi_file["guid"])
    return keys

def load_uefi_volume(firmware_id, data, object_id= None):
    object_id = firmware_id if object_id is None else object_id
    firmware_volume = uefi.FirmwareVolume(data)
    if not firmware_volume.valid_header:
        print "This is not a valid UEFI firmware volume (%s)." % object_id
        return None
    if not firmware_volume.process():
        print "The UEFI firmware volume (%s) did not parse correctly." % object_id
        return None

    if not objects_table.get_all(object_id, index="object_id").is_empty().run():
        print "Firmware volume object (%s) exists." % object_id
        return object_id

    ### Store the files
    objects = firmware_volume.iterate_objects(True)
    files = get_files(objects)

    ### Store the volume object information
    child_ids = []
    for uefi_file in files:
        child_ids += store_file(object_id, uefi_file)    

    objects_table.insert({
        "firmware_id": firmware_id,
        "object_id": object_id,
        "children": child_ids,
        ### Store size, type, attrs
        "type": "uefi_volume",
        "size": len(data)
        ### Todo: store volume-specific attributes
    }).run()

    return object_id

    pass

def load_uefi_capsule(firmware_id, data, object_id= None):
    object_id = firmware_id if object_id is None else object_id
    capsule = uefi.FirmwareCapsule(data)
    if not capsule.valid_header:
        print "This is not a valid UEFI firmware capsule (%s)." % object_id
        #sys.exit(1)
        return None
    capsule.process()
    #if not capsule.process():
    #    return None

    ### Create the parent object
    if not objects_table.get_all(object_id, index="object_id").is_empty().run():
        print "Firmware capsule object (%s) exists." % object_id
        return object_id

    ### Only handle capsule's filed with firmware volumes?
    volume = capsule.capsule_body
    objects = volume.iterate_objects(True)
    files = get_files(objects)

    child_ids = []
    for uefi_file in files:
        child_ids += store_file(object_id, uefi_file)

    objects_table.insert({
        "firmware_id": firmware_id,
        "object_id": object_id,
        "children": child_ids,
        ### Store size, type, attrs
        "type": "uefi_capsule",
        "size": len(data)
        ### Todo: store capsule-specific attributes
    }).run()

    ### Not storing capsule content (yet), may be too much data.
    return object_id
    pass

def load_pfs(firmware_id, data):
    pfs = PFSFile(data)
    if not pfs.check_header():
        print "This is not a valid DELL PFS update."
        sys.exit(1)

    pfs.process()

    ### Store PFS info
    if not objects_table.get_all(firmware_id, index="object_id").is_empty().run():
        print "PFS object (%s) exists." % firmware_id
        return

    child_ids = []
    for section in pfs.objects:
        section_info = section.info(include_content= True)

        if not objects_table.get_all(firmware_id, index="firmware_id").filter({"guid": section_info["guid"]}).is_empty().run():
            print "Skipping PFS (%s) GUID %s, object exists." % (firmware_id, section_info["guid"])
            continue

        section_id = get_firmware_id(section_info["content"])
        section_info["object_id"] = section_id
        #section_info["chunks"] = [base64.b64encode(chunk) for chunk in section_info["chunks"]]

        for chunk in section_info["chunks"]:
            store_content(firmware_id, section_id, chunk, content_type= "pfs_chunk")

        object_keys = load_uefi_volume(firmware_id, section_info["content"], object_id= section_id)
        if object_keys is None:
            ### This section is not a UEFI-volume.
            object_keys = store_object(firmware_id, section_info, object_type= "pfs_section")
        if object_keys is not None:
            child_ids += object_keys

        print "Stored PFS section (%s) GUID %s." % (firmware_id, section_info["guid"])
        #load_uefi_volumes(section_id, section_info["content"])

    objects_table.insert({
        "firmware_id": firmware_id,
        "object_id": firmware_id,
        "children": child_ids,
        ### Store size, type, attrs
        "type": "dell_pfs",
        "size": len(data)
        ### Todo: store capsule-specific attributes
    }).run()
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

def get_result_keys(insert_object):
    return insert_object["generated_keys"]

ITEM_TYPES = {
    "capsule": "uefi_capsule",
    "pfs": "dell_pfs",
    "me": "intel_me",
    "bios": "bios_rom",
    "volume": "uefi_volume"
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
    objects_table = db.table("objects")
    updates_table = db.table("updates")
    content_table = db.table("content")

    label_type = "unknown"
    if args.pfs: label_type = ITEM_TYPES["pfs"]
    elif args.bios: label_type = ITEM_TYPES["bios"]
    elif args.me: label_type = ITEM_TYPES["me"]
    elif args.capsule: label_type = ITEM_TYPES["capsule"]
    else: label_type = ITEM_TYPES["volume"]

    set_update(firmware_id, input_data, label_type, item_id= args.item)

    if args.pfs:
        load_pfs(firmware_id, input_data)
    elif args.capsule:
        load_uefi_capsule(firmware_id, input_data)
    else:
        load_uefi_volume(firmware_id, input_data)



