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
    files = {}

    for index in volumes:
        volume_files = _parse_firmware_volume(data[index-40:], name=index)
        for key, value in volume_files.iteritems():
            files[key] = value
    return files
    pass

def get_name(_object):
    if len(_object["label"]) > 0: return _object["label"]
    if "objects" not in _object: return None
    #print {key:value for key,value in _object.iteritems() if key != "objects"}
    for _sub_object in _object["objects"]:
        #print {key:value for key,value in _sub_object.iteritems() if key != "objects"}
        if len(_sub_object["label"]) > 0: return _sub_object["label"]
    for _sub_object in _object["objects"]:
        _name =  get_name(_sub_object)
        if _name is not None: return _name
    return None

def show_file(_object):
    return {key:value for key,value in _object.iteritems() if key not in ["objects", "content"]}

def show_files(objects):
    for _object in objects:
        if _object["type"] == "FirmwareFile":
            print _object["guid"], get_name(_object), _object["attrs"]
        else:
            print _object["type"], {key:value for key,value in _object.iteritems() if key != "objects"}
        if "objects" in _object:
            show_files(_object["objects"])

def get_files(objects):
    files = {}
    for _object in objects:
        if _object["type"] == "FirmwareFile":
            files[_object["guid"]] = {"name": get_name(_object)}
            for key, value in _object["attrs"].iteritems():
                files[_object["guid"]][key] = value
            # Deep copy the object incase there's nested files, no recursive pointers.
            files[_object["guid"]]["objects"] = copy.deepcopy(_object["objects"])
            files[_object["guid"]]["content"] = _object["content"]
            files[_object["guid"]]["guid"] = _object["guid"]
            files[_object["guid"]]["md5"] = hashlib.md5(_object["content"]).hexdigest()
        if "objects" in _object:
            for key, value in get_files(_object["objects"]).iteritems():
                files[key] = value
    return files

def _guid_strings(_object):
    guids = []
    if "type" in _object and _object["type"] == 0x18:
        guids += list(_strings(_object["content"], min=3))
    if "attrs" in _object and "type" in _object["attrs"] and _object["attrs"]["type"] == 0x18:
        guids += list(_strings(_object, min=3, no_guid= True))
    if "objects" in _object:
        for _sub_object in _object["objects"]:
            guids += _guid_strings(_sub_object)
    return guids

def _strings(_object, min=10, no_guid= False):
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
    if no_guid is False:
        for _string in _guid_strings(_object):
            yield _string

def _find_pe(_object):
    if "objects" in _object:
        for _sub_object in _object["objects"]:
            if _sub_object["type"] not in ["FirmwareFileSystemSection", "CompressedSection"]:
                continue
            sub_content = _find_pe(_sub_object)
            if sub_content is not None: return sub_content
    if "attrs" not in _object: return None
    if "type_name" not in _object["attrs"]: return None
    if _object["attrs"]["type_name"] in ["PE32 image"]:
        return _object
    return None

def _load_pe(files):
    _types = {267: "x86", 523: "x86_64"}
    for key in files:
        pe_object = _find_pe(files[key])
        if pe_object is None: continue

        files[key]["sections"] = {}
        pe = pefile.PE(data= pe_object["content"])
        files[key]["machine_type"] = pe.FILE_HEADER.Machine
        files[key]["compile_time"] = pe.FILE_HEADER.TimeDateStamp
        files[key]["subsystem"] = pe.OPTIONAL_HEADER.Subsystem

        for section in pe.sections:
            #pe_1_sections[section.Name.replace("\x00", "")] = section
            files[key]["sections"][section.Name.replace("\x00", "")] = base64.b64encode(section.get_data(0))
            files[key]["sections"][section.Name.replace("\x00", "") + "_md5"] = hashlib.md5(section.get_data(0)).hexdigest()

def _load_strings(files):
    for key in files:
        files[key]["strings"] = list(_strings(files[key]))




def _encode(files):
    def _encode_object(_object):
        if "content" in _object.keys():
            if _object["content"] is None: _object["content"] = ""
            else: _object["content"] = base64.b64encode(_object["content"])
        if "objects" in _object.keys() and len(_object["objects"]) > 0:
            for _sub_object in _object["objects"]:
                _encode_object(_sub_object)
    for key in files.keys():
        _encode_object(files[key])

def _parse_firmware_volume(data, name="volume"):
    firmware_volume = FirmwareVolume(data, name)
    firmware_volume.process()

    objects = firmware_volume.iterate_objects(True)
    return get_files(objects)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #parser.add_argument("--save-pe", help='Save a PE by canonical name')
    #parser.add_argument("--save-content", help= "Save entire content")
    #parser.add_argument("--date", required=True, help="date the firmware was released")
    #parser.add_argument("--version", required=True, help="Version")
    #parser.add_argument("--system", required=True, help="the system")
    #parser.add_argument("--manuc", required=True, help="the manufacturer")
    parser.add_argument("file", help="The file to work on")
    #parser.add_argument("file2", help="File to compare")
    args = parser.parse_args()



    try:
        with open(args.file, 'rb') as fh: input_data_1 = fh.read()
    except Exception, e:
        print "Error: Cannot read file (%s) (%s)." % (args.file, str(e))
        sys.exit(1)

    file_id = hashlib.md5(input_data_1).hexdigest()

    files_1 = _brute_search(input_data_1)
    _load_pe(files_1)
    _load_strings(files_1)
    _encode(files_1)
    #files_2 = _brute_search(input_data_2)

    r.connect("localhost", 28015).repl()
    for key in files_1:
        files_1[key]["firmware_id"] = file_id
        #print files_1[key]
        #sys.exit(1)
        try:
            r.db("firmware").table("uefi_files").insert(files_1[key]).run()
        except Exception, e:
            print str(e), key
        #sys.exit(1)

