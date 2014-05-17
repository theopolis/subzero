Subzero
=======
Firmware analysis gone wild. 

This project includes both a web interface and a set of importing and map/reduction scripts used for vulnerability analysis on Firmware Updates (specifically those parsed by uefi-firmware-parser.) The import of firmware is complimented with the descriptions and metadata mined from uefi-spider in JSON form. This web interface will eventually include a submission form used to detect/match unknown updates against the corpus of imported data.

Installation
------------
Subzero provides a ``db_setup.py`` script that creates the RethinkDB database on the `localhost` server. This script can be run multiple time until it completes if it does error initially. It should create the tables used by the application and the required table indexes. 

::

  $ (cd web && bundle install()
  $ (cd scripts && python ./db_setup.py)

**Requirements**

- RethinkDB (python rethinkdb)
- ssdeep (pydeep)
- python-magic
- Ruby/Rails (and the associated gems)
- This project consumes output from uefi-spider and uefi-firmware-parser.

Note: Rethink may need to be compiled from source with a minor change to the max array size limit. With a large number of updates the maximum array size (100k) is quickly exceeded for most of the map/reductions.

Usage
-----

**Subzero application**
::

  $ cd web && rails s

**Firmware import**

The importing process uses 4 steps, and assumes you have downloaded or crawled
firmware update either from vendors or an enterprise: 
(1) Importing metadata about the updates; 
(2) Parsing and importing a hierarchy of components within a single firmware update;
(3) Comparing product updates and vendor statistics; 
(4) Scheduling map/reductions to generate statistics on the firmware corpus.

Step 2 is quite involved and uses multiple scripts specific to each vendor supported by Subzero. Since each vendor distributes their firmware uniquely, these scripts must preprocess and extract firmware components such as flash descriptors, UEFI Volumes, or other non-monolithic blobs for import. Once this data is isolated
Subzero can use specifications and standards (and a lot of python) to parse each subcomponent and store the binary content and hierarchy of relations (a tree).

*Example*
::

  $ cd scripts
  $ python ./fv_scrapy.py -t Dell -d /path/to/dell/updates/
  [...]
  $ python ./fv_load.py --pfs -i Dell-O990-A05 \
      /path/to/dell/updates/Dell-O990-A05/update.exe.hdr
  [...]

 Where this last command is repeated for each firmware update imported.
 There are example scripts that automate this importing.

**Stats Generation**

Of the previous section, the statistics generation comprises steps 3 and 4.
It's simple to add additional statistics and save them into RethinkDB. 
There are special indexes created to assist with rapidly adding additional reductions.

*Example*
::

  $ cd scripts
  $ python ./fv_dbcontrol.py load_change --vendor Dell
  $ python ./fv_dbcontrol.py load_meta --vendor Dell
  $ python ./db_mapreduce.py guid_group

In this example all of Dell's firmware updates will compare their binary changes
time deltas and added or removed firmware features. Then each of the content sections with every Dell firmware will run against magic and optionally have their ASCII strings parsed and stored. Finally every UEFI guid will be mapped and counted.

**Features**

- WebUI display of UEFI, Flash, and other firmware formats.
- Graph-views of vendor update frequency, metadata, and firmware changes.
- Vulnerability analysis through a variety of techniques.
- Export and download of firmware components.

**Supported Vendors**

Subzero has been tested on BIOS/UEFI/firmware updates from the following vendors.
Not every update for every product will parse, some may required a-prioi decompression
or extraction from the distribution update mechanism (typically a PE). 

- ASRock
- Dell
- Gigabyte
- Intel
- Lenovo
- HP
- MSI
- VMware

