"""
Read scrapy-generated JSON files specific to each scraped BIOS vendor.
Store results in RethinkDB.
"""

import os, sys
import argparse
import json
from datetime import datetime
import rethinkdb as r

'''
IntelSpider:
{
  "binary": "", 
  "bios_url": "http://downloadmirror.intel.com/15909/eng/EC0072.BIO", 
  "products": [
    "Intel\u00ae Desktop Board DG35EC"
  ], 
  "attrs": {
    "status": "Previously Released", 
    "name": "BIOS Update [ECG3510M.86A]", 
    "url": "/Detail_Desc.aspx?agr=Y&DwnldID=15909&ProdId=3598&lang=eng", 
    "date": "5/13/2008", 
    "version": "0072", 
    "item_id": "15909", 
    "desc": "Three methods for updating your Intel\u00ae Desktop Board\u2019s BIOS version."
  }, 
  "item_id": "15909", 
  "notes_url": "http://downloadmirror.intel.com/15909/eng/EC_0072_ReleaseNotes2.pdf"
}

Dell Spider:
{
  "previous_versions": [
    [
      "A09", 
      "http://www.dell.com//support/drivers/us/en/19/DriverDetails?driverId=4RR90", 
      "10/12/2012 8:56:52 AM", 
      "4RR90"
    ], 
  ],
  "binary": "", 
  "importance": "Recommended", 
  "fixes": "* Added support for an option to disable predictive memory failure reporting using the Deployment Toolkit.\n* Added TXT-SX support\n* Increased single-bit error logging threshold\n* Ensure BIOS has enabled processor AES-NI before booting to the operating system.\n* Updated the iDRAC Configuration Utility\n* Updated the embedded 5709 UEFI driver to version 6.0.0\n* Updated MRC\n* Updated Intel(R) Xeon(R) Processor 5600 Series B1 stepping microcode (Patch ID=0x13)\n* Added SR-IOV support\n* Updated the embedded 5709C PXE/iSCSI option ROM to version 6.0.11", 
  "version": "2.2.10", 
  "notes_url": "", 
  "attrs": {
    "url": "http://www.dell.com/support/drivers/us/en/19/DriverDetails?driverId=6NP3V", 
    "release_date": "1/12/2012 (Latest Version)", 
    "driver_type": "BIOS Updates", 
    "compatibility": [
      "Enterprise Servers T610", 
      " Powervault DL2200", 
      " Enterprise Servers R910"
    ]
  }, 
  "item_id": "6NP3V", 
  "file_names": [
    "T610-020210C.exe", 
    "PET610_BIOS_WIN_2.2.10.EXE", 
    "PET610_BIOS_LX_2.2.10.BIN"
  ], 
  "bios_urls": [
    "http://downloads.dell.com/FOLDER45071M/1/T610-020210C.exe", 
    "http://downloads.dell.com/FOLDER82696M/1/PET610_BIOS_WIN_2.2.10.EXE", 
    "http://downloads.dell.com/FOLDER71962M/1/PET610_BIOS_LX_2.2.10.BIN"
  ]
}

HP Spider:
  "binary": "", 
  "bios_url": "http://ftp.hp.com/pub/softpaq/sp54501-55000/sp54636.exe", 
  "importance": "Critical", 
  "ssm": "YES", 
  "version": "F.20 PASS1", 
  "notes_url": "...", 
  "attrs": {
    "url": "...", 
    "date": "2011-09-09", 
    "item_id": "ob_102534_1", 
    "name": "HP Notebook System BIOS Update"
  }, 
  "item_id": "ob_102534_1", 
  "binary_name": "sp54636.exe", 
  "compatibility": [
    "HP ProBook 4320s Notebook PC", 
    "HP ProBook 4321s Notebook PC", 
    "HP ProBook 4420s Notebook PC", 
    "HP ProBook 4421s Notebook PC"
  ], 
  "desc": "...",
  "previous_versions": [[], []]
}


'''

CACHE_TIMES = {}

def load_details(details, file_name= "None"):
  global CACHE_TIMES

  if "attrs" not in details:
    print "Warning: no attrs in details (%s)." % file_name
  update = {"item_id": details["item_id"]}
  
  if args.type == "HP":
    try:
      update["products"] = [p.strip() for p in details["compatibility"]]
    except:
      update["products"] = ["Unknown System"]
    update["payload_urls"] = [details["bios_url"]]
    update["name"] = details["binary_name"]
    update["date"] = int(datetime.strptime(details["attrs"]["date"], "%Y-%m-%d").strftime("%s"))
    update["version"] = details["version"]
    update["description"] = details["desc"] if "desc" in details else ""
    update["notes_url"] = details["notes_url"]
    update["details_url"] = details["attrs"]["url"]

    update["attrs"] = {}
    update["attrs"]["importance"] = details["importance"] if "importance" in details else "Unknown"
    if "ssm" in details:
      update["attrs"]["ssm"] = details["ssm"]
    update["attrs"]["title"] = details["attrs"]["name"]

    update["previous_versions"] = []
    if "previous_versions" in details:
      for version in details["previous_versions"]:
        update["previous_versions"].append({
          "version": version[0],
          "item_id": version[2],
          "details_url": version[1]
        })
    update["vendor"] = "HP"

  if args.type == "ASRock": 
    update["products"] = [details["attrs"]["product"]]
    update["payload_urls"] = [details["bios_url"]]
    update["name"] = details["binary_name"]
    update["date"] = int(datetime.strptime(details["date"], "%m/%d/%Y").strftime("%s"))
    update["version"] = details["version"]
    update["description"] = details["desc"]
    update["notes_url"] = ""
    update["details_url"] = details["attrs"]["url"]
    update["attrs"] = {}
    update["attrs"]["update_type"] = details["bios_type"]
    update["attrs"]["chipset"] = details["attrs"]["chipset"]
    update["vendor"] = "ASRock"

  if args.type == "Lenovo":
    update["products"] = details["products"]
    update["payload_urls"] = [details["bios_url"]]
    update["name"] = details["binary_name"]
    try:
      update["date"] = int(datetime.strptime(details["date"], "%Y/%m/%d").strftime("%s"))
    except:
      update["date"] = 0
    update["version"] = details["version"]
    update["description"] = details["desc"]
    update["notes_url"] = details["notes_url"]
    update["details_url"] = details["url"]
    update["attrs"] = {}
    update["attrs"]["update_type"] = "default"
    update["vendor"] = "Lenovo"

  if args.type == "MSI":
    update["products"] = [details["attrs"]["title"]]
    update["payload_urls"] = [details["bios_url"]]
    update["name"] = details["binary_name"]
    update["date"] = int(datetime.strptime(details["date"], "%Y-%m-%d").strftime("%s"))
    update["version"] = details["version"]
    update["description"] = details["desc"] if "desc" in details else ""
    update["notes_url"] = ""
    update["details_url"] = details["attrs"]["url"]
    update["attrs"] = {}
    update["attrs"]["importance"] = "default"
    update["attrs"]["title"] = details["attrs"]["title"]
    update["attrs"]["driver_type"] = details["driver_type"]
    update["vendor"] = "MSI"

  if args.type == "Dell":
    update["products"] = [p.strip() for p in details["attrs"]["compatibility"]]
    update["payload_urls"] = details["bios_urls"]
    update["name"] = details["file_names"][0] # Could be improved
    ### This is the date, there is a timestamp found in a previous version
    update["date"] = int(datetime.strptime(details["attrs"]["release_date"].split("(", 1)[0].strip(), "%m/%d/%Y").strftime("%s"))
    update["version"] = details["version"]
    update["description"] = details["fixes"]
    update["notes_url"] = ""
    update["details_url"] = details["attrs"]["url"]

    update["attrs"] = {}
    update["attrs"]["importance"] = details["importance"]
    update["previous_versions"] = []
    for version in details["previous_versions"]:
      update["previous_versions"].append({
        "version": version[0],
        "date": int(datetime.strptime(version[2], "%m/%d/%Y %H:%M:%S %p").strftime("%s")),
        "item_id": version[3],
        "details_url": version[1]
      })
      CACHE_TIMES[version[3]] = int(datetime.strptime(version[2], "%m/%d/%Y %H:%M:%S %p").strftime("%s"))
    update["vendor"] = "Dell"
    pass

  elif args.type == "Intel":
    update["products"] = [p.replace(u"Intel\u00ae", "").strip() for p in details["products"]]
    ### Only one URL for intel
    update["payload_urls"] = [details["bios_url"]]
    update["name"] = details["attrs"]["name"]
    update["date"] = int(datetime.strptime(details["attrs"]["date"], "%m/%d/%Y").strftime("%s"))
    update["version"] = details["attrs"]["version"]
    update["description"] = details["attrs"]["desc"]
    update["notes_url"] = details["notes_url"]
    update["details_url"] = details["attrs"]["url"]

    update["attrs"] = {}
    update["attrs"]["status"] = details["attrs"]["status"]
    update["vendor"] = "Intel"

  #print json.dumps(update, indent=2)
  return update
  pass

def save_update(update):
  if not table.filter({"item_id": update["item_id"]}).is_empty():
    print "ItemID: %s is a duplicate, skipping." % update["item_id"]
    return
  table.insert(update)
  pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", action="store_true", default= False, help= "Treat the input as a directory")
    parser.add_argument("-t", "--type", default= None, help= "Force parsing a file of a specific ISV, otherwise guess.")
    parser.add_argument("file", help="The file to work on")
    args = parser.parse_args()

    r.connect("localhost", 28015).repl()
    table = r.db("uefi").table("updates")

    all_files = []
    if args.directory:
      if not os.path.isdir(args.file):
        print "Error: %s is not a directory." % args.file
        sys.exit(1)
      for root, dirs, files in os.walk(args.file):
        for file_name in files:
          file_name = os.path.join(root, file_name)
          _, extension = os.path.splitext(file_name)
          if extension != ".json":
            continue
          all_files.append(file_name)
    else:
      all_files.append(args.file)

    updates = []
    for file_name in all_files:
      try:
        with open(file_name, 'r') as fh:
          details = fh.read()
        details = json.loads(details)
      except Exception, e:
        print "Error: cannot load (%s). (%s)" % (file_name, str(e))
        continue

      try:
        update = load_details(details, file_name)
      except Exception, e:
        print "Failed for %s, %s." % (file_name, str(e))
        continue
      if not table.get_all(update["item_id"], index="item_id").is_empty().run():
        print "ItemID: %s is a duplicate, skipping." % update["item_id"]
        continue
      updates.append(update) 
      pass

    ### Now update the precision using cached times.
    if len(CACHE_TIMES) > 0:
      for update in updates:
        if update["item_id"] in CACHE_TIMES:
          update["date"] = CACHE_TIMES[update["item_id"]]

    ### Apply all updates
    table.insert(updates).run()

