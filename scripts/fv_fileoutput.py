import argparse
import hashlib
import base64
import pefile
import os

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
            files[_object["guid"]]["objects"] = _object["objects"]
            files[_object["guid"]]["content"] = _object["content"]
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

def file_compare(key, file1, file2):

    md5_1 = hashlib.md5(file1["content"]).hexdigest()
    md5_2 = hashlib.md5(file2["content"]).hexdigest()

    if md5_1 == md5_2: return 0

    #if md5_1 != md5_2:
    #    print "%s content is different: %s %s" % (key, md5_1, md5_2)
    #    print " ", show_file(value)
    #    print " ", show_file(files_2[key])
    pe_object1 = _find_pe(file1)
    pe_object2 = _find_pe(file2)


    if pe_object1 is None or pe_object2 is None:
        if file1["size"] != file2["size"]:
            print "%s (%s) sizes are different (no PE): %d %d" % (key, file1["name"], file1["size"], file2["size"])
            return True
        print "%s (%s) md5s are different (no PE): %d %d" % (key, file1["name"], file1["size"], file2["size"])
        return True

    try:
        pe_object1["content"] = base64.b64decode(pe_object1["content"])
        pe_object2["content"] = base64.b64decode(pe_object2["content"])
    except Exception, e: pass

    try:
        pe_1 = pefile.PE(data= pe_object1["content"])
        pe_1_sections = {}
        for section in pe_1.sections:
            pe_1_sections[section.Name.replace("\x00", "")] = section

        pe_2 = pefile.PE(data= pe_object2["content"])
        pe_2_sections = {}
        for section in pe_2.sections:
            pe_2_sections[section.Name.replace("\x00", "")] = section
    except Exception, e:
        print "%s does not contain a DOS header?" % key
        return True

    #for section_name in pe_1_sections:
        #print (section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)

        #if section_name not in pe_2_sections:
        #    print "%s does not contain section (%s)." % (key, section_name)
        #    return True
    text_1 = pe_1_sections[".text"].get_data(0)
    text_2 = pe_2_sections[".text"].get_data(0)
    #pe_2.sections[0].get_data(0)

    if len(text_1) != len(text_2):
        print "%s (%s) .text sizes are different: %d %d" % (key, file1["name"], file1["size"], file2["size"])
        return True

    if text_1 != text_2:
        byte_mismatch_count = 0
        for i in xrange(len(text_1)):
            if text_1[i] != text_2[i]: byte_mismatch_count += 1
        print "%s (%s) .text section mis-match (%d bytes, %d total)" % (key, file1["name"], byte_mismatch_count, len(text_1))
        #for l in _strings(pe_object1): print l
        return True

    #print "%s (%s) some other section is different: %d %d" % (key, file1["name"], file1["size"], file2["size"])
    #return True

    #print section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData
    #sys.exit(1)

    #pe_2 = pefile.PE(data= pe_object2["content"])

    pass

def _parse_firmware_volume(data, name="volume"):
    firmware_volume = FirmwareVolume(data, name)
    firmware_volume.process()

    objects = firmware_volume.iterate_objects(True)
    return get_files(objects)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--save-pe", help='Save a PE by canonical name')
    parser.add_argument("--save-content", help= "Save entire content")
    parser.add_argument("file", help="The file to work on")
    parser.add_argument("file2", help="File to compare")
    args = parser.parse_args()

    try:
        with open(args.file, 'rb') as fh: input_data_1 = fh.read()
    except Exception, e:
        print "Error: Cannot read file (%s) (%s)." % (args.file, str(e))
        sys.exit(1)

    try:
        with open(args.file2, 'rb') as fh: input_data_2 = fh.read()
    except Exception, e:
        print "Error: Cannot read file (%s) (%s)." % (args.file2, str(e))
        sys.exit(1)

    files_1 = _brute_search(input_data_1)
    files_2 = _brute_search(input_data_2)

    for key, value in files_1.iteritems():
        if key not in files_2:
            print "%s not in %s" % (key, os.path.basename(args.file)), show_file(value)
    for key, value in files_2.iteritems():
        if key not in files_1:
            print "%s not in %s" % (key, os.path.basename(args.file2)), show_file(value)

    different_count = 0
    for key, value in files_1.iteritems():
        if key not in files_2: continue
        if file_compare(key, value, files_2[key]):
            different_count += 1
    print "%d files, %d different files" % (len(files_1), different_count)

    if args.save_pe is not None:
        pe_1 = _find_pe(files_1[args.save_pe])
        pe_2 = _find_pe(files_2[args.save_pe])

        with open('%s_1' % args.save_pe, 'w') as fh: fh.write(pe_1["content"])
        with open('%s_2' % args.save_pe, 'w') as fh: fh.write(pe_2["content"])

    if args.save_content is not None:
        with open("%s_1" % args.save_content, 'w') as fh: fh.write(files_1[args.save_content]["content"])
        with open("%s_2" % args.save_content, 'w') as fh: fh.write(files_2[args.save_content]["content"])


