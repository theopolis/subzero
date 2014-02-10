import argparse
import hashlib
import pefile
import os
import base64
import copy

import rethinkdb as r

from uefi_firmware import *

def _brute_search(data):
    volumes = search_firmware_volumes(data)
    objects = []

    for index in volumes:
        objects += _parse_firmware_volume(data[index-40:], name=index)
    return objects
    pass

def _parse_firmware_volume(data, name="volume"):
    firmware_volume = FirmwareVolume(data, name)
    firmware_volume.process()

    objects = firmware_volume.iterate_objects(True)
    return objects

def get_file_name(_object):
    if len(_object["label"]) > 0:
        return _object["label"]
    if not "objects" in _object:
        return None
    for _sub_object in _object["objects"]:
        if not isinstance(_sub_object["_self"], EfiSection):
            continue
        name = get_file_name(_sub_object)
        if name is not None:
            return name
    return None

def get_file_description(_object):
    if isinstance(_object["_self"], FreeformGuidSection):
        return _object["label"]
    if "objects" not in _object:
        return None
    for _sub_object in _object["objects"]:
        if not isinstance(_sub_object["_self"], EfiSection):
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
    return {key: value for key, value in _object.iteritems() if key in ["guid", "type", "attrs"]}

def store_object(_object):
    if "_self" in _object:
        if not isinstance(_object["_self"], EfiSection):
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
        key = store_object(_sub_object)
        if key is not None:
            children += key
    return children

def store_file(file):
    entry = _object_entry(file)

    if not db.table("files").filter({"firmware_id": firmware_id, "guid": file["guid"]}).is_empty().run():
        '''If the file already exists for this GUID/FirmwareID pair, skip.'''
        return

    children = []
    for _object in file["objects"]:
        children += store_object(_object)
    #print children

    if len(children) == 0:
        print "Storing a cloned child for (%s)." % file["guid"]
        entry["no_children"] = True
        children += store_object(file)

    entry["children"] = children
    entry["firmware_id"] = firmware_id
    entry["content"] = base64.b64encode(file["content"])
    entry["name"] = file["name"]
    entry["description"] = file["description"]

    db.table("files").insert(entry).run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="The file to work on")

    args = parser.parse_args()

    try:
        with open(args.file, 'rb') as fh: input_data = fh.read()
    except Exception, e:
        print "Error: Cannot read file (%s) (%s)." % (args.file, str(e))
        sys.exit(1)

    firmware_id = hashlib.md5(input_data).hexdigest()
    objects = _brute_search(input_data)
    
    r.connect("localhost", 28015).repl()
    db = r.db("uefi")

    if not db.table("updates").filter({"firmware_id": firmware_id}).is_empty().run():
        ### Add size of the firmware to the updates table
        db.table("updates").filter({"firmware_id": firmware_id}).update({
            "size": len(input_data)
        }).run()

    files = get_files(objects)
    for key in files:
        store_file(files[key])


