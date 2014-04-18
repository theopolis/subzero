require 'rethinkdb'
#require "base64"

include RethinkDB::Shortcuts

class DbController < ApplicationController
  before_filter :db_connect

private
  def db_connect
  	r.connect(:host => "localhost").repl
    @db = r.db("uefi")
    @objects_table = r.db("uefi").table("objects")
    @stats_table   = r.db("uefi").table("stats")
    @updates_table = r.db("uefi").table("updates")
    @content_table = r.db("uefi").table("content")
    @lookup_table  = r.db("uefi").table("lookup")
  end

  def update_dict(doc)
  	return {
      :name => doc["name"], 
      :version => doc["version"], 
      :date => doc["date"], 
      :vendor => doc["vendor"], 
      :item_id => doc["item_id"],
      :firmware_id => doc["firmware_id"],
      :size => doc["size"],
      :status => doc["attrs"]["status"],
      :load_change => if doc.has_key?("load_change") then doc["load_change"] else {} end,
      :stats => doc["stats"],

      :actions => if doc.has_key?("actions") then doc["actions"] else nil end,
      :importance => doc["attrs"]["importance"]
    }
  end

  def object_query(sequence)
    return sequence.map{|doc| r.branch(doc.has_fields([:guid]), doc.merge({
        ### Add in map-reduces
        "shared" => @stats_table.get_all(["uefi_guid", doc[:guid]], :index => "type_key").pluck("result").coerce_to('array'),
        "matches" => @stats_table.get_all(["object_id", doc[:object_id]], :index => "type_key").pluck("result").coerce_to('array'),
        "lookup" => @lookup_table.get_all(doc[:guid], :index => "guid").coerce_to("array")
      }), doc.merge({})
      )}.map{|doc|doc.merge({
        "content" => @content_table.get_all(doc["object_id"], :index => "object_id").pluck("attrs", "load_meta").coerce_to("array")
      })}.order_by(r.desc(lambda {|doc| doc[:size]}))
  end

  def object_stats! (_obj)

  end

  def percent_change (_obj)
    size = _obj.has_key?("size") ? _obj["size"] : _obj["attrs"]["size"]
    score = _obj["load_change"]["change_score"]
    return (score/(size * 1.0))*100
  end

  def lookups
    if @lookups != nil then return @lookups end

    ### Search for optional lookup values which better describe each file
    @lookups = {}
    cursor = r.db("uefi").table("lookup").run
    cursor.each{ |lookup| @lookups[lookup["guid"]] = lookup }
    return @lookups
  end

  def add_object_stats! (obj, attrs = true, meta = true)
    obj["stats"] = {}
    if attrs then obj["stats"] = obj["attrs"] end
    if meta and obj.has_key?("content") and obj["content"].length > 0
      if obj["content"][0].has_key?("load_meta")
        #obj["stats"]["Magic"] = obj["content"][0]["load_meta"]["magic"]
        obj["load_meta"] = obj["content"][0]["load_meta"]
        #obj["stats"].merge(obj["content"][0]["load_meta"]) 
      end
    end

    if obj.has_key? ("load_change")
      if obj["load_change"].has_key? ("change_score") and obj["load_change"]["change_score"] > 0
        obj["stats"]["Changed"] = "%d bytes, %.2f%%" % [obj["load_change"]["change_score"], percent_change(obj)]
      end
      if obj["load_change"].has_key? ("new_file")
        obj["stats"]["New File"] = true
      end
    end
  end

  def add_lookups! (_obj)
    lookups = lookups()
    if lookups.has_key?(_obj["guid"])
      lookups[_obj["guid"]].each do |key, value|
        next if ["guid", "id"].include?(key)
        _obj[key] = "*%s" % value
      end
    end
  end

  def get_object_info(_obj)
    ### Requires: firmware_id, children, attrs
    #@firmware_id = obj["firmware_id"]
    add_lookups!(_obj)
    add_object_stats!(_obj, attrs = false, meta = true)

    ### This is a different type of stats
    objects_count = if _obj.has_key?("children") then _obj["children"].length else 0 end
    unless objects_count == 0 then _obj["stats"]["Children"] = objects_count end

    ### Handle various lookups data from lookup table
    if _obj.has_key?("lookup") and _obj["lookup"].length > 0
      if _obj["lookup"][0].has_key?("guid_name") then _obj["guid_name"] = _obj["lookup"][0]["guid_name"] end
      if _obj["lookup"][0].has_key?("guid_actions") then _obj["guid_actions"] = _obj["lookup"][0]["guid_actions"] end
    end

    unless _obj.has_key?("attrs") then _obj["attrs"] = {} end
    if _obj["type"] == "uefi_file"
      _obj["info"] = {
        #"Attrs" => _obj["attrs"]["attributes"],
        "FileType" => _obj["attrs"]["type_name"],
      }

      ### Requires a map-reduce
      unless _obj["shared"].length == 0 then _obj["stats"]["Shared"] = _obj["shared"][0]["result"] end
      unless _obj["matches"].length == 0 then _obj["stats"]["Matches"] = _obj["matches"][0]["result"] end
    else
      if _obj.has_key?("attrs") and _obj["attrs"].has_key?("type_name")
        _obj["info"] = {
          "SectionType" => _obj["attrs"]["type_name"]
        }
      end
    end

    return _obj
  end

end
