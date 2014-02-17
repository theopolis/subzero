require 'rethinkdb'
require "base64"

include RethinkDB::Shortcuts

class ExplorerController < ApplicationController
  before_filter :db_connect

  # GET /explorer
  def explorer
  	@firmware = {}

  	updates = r.db("uefi").table("updates").
      order_by(r.asc(lambda {|doc| doc[:version]})).run
  	updates.each do |doc|
      if doc.has_key? ("load_change")
        #p (doc["load_change"]["change_score"]/doc["size"])*100
        doc["stats"] = {
          "Changed" => "#{doc["load_change"]["change_score"]} bytes, %.2f%" % [percent_change(doc)]
        }
        if doc["load_change"].has_key? ("new_files")
          doc["stats"]["Added Files"] = "%d, %d bytes" % [doc["load_change"]["new_files"].length, doc["load_change"]["new_files_score"]]
        end
      end

      ### Organize firmware updates by machine
      unless @firmware.has_key?(doc["machine"])
        @firmware[doc["machine"]] = []
      end

  	  @firmware[doc["machine"]].push(doc)
  	end
  end

  def download
    @object_id = params[:object_id]

    object = r.db("uefi").table("objects").get(@object_id).run
    if object == nil
      return
    end

    send_data Base64.decode64(object["content"]), :filename => "%s-%s.obj" % [object["firmware_id"], object["guid"]]

  end

  def file
    @firmware_id = params[:firmware_id]
    @guid = params[:id]

    ### Get Information about File
    cursor = r.db("uefi").table("files").filter{|file| 
        (file["firmware_id"].eq(@firmware_id)) & (file["guid"].eq(@guid))
      }.pluck("name", "guid", "description", "attrs", "load_change", "size").limit(1).run

    ### Silly construct
    cursor.each do |file|
      @file = file
      break
    end

    ### Stats will display a table of key=>value details
    @stats = {
      "name" => @file["name"],
      "description" => @file["description"],
    }
    @stats = @stats.deep_merge(@file["attrs"])

    ### Collect objects within this file
    @objects = []
    cursor = r.db("uefi").table("objects").filter{|obj| 
        (obj["firmware_id"].eq(@firmware_id)) & (obj["guid"].eq(@guid))
      }.pluck("attrs", "load_meta", "id").
      order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run

    cursor.each do |obj|
      obj["stats"] = obj["attrs"]
      if obj.has_key?("load_meta")
        obj["stats"] = obj["stats"].merge(obj["load_meta"])
      end

      @objects.push(obj)
    end

    ### This applies to objects
    if @file.has_key?("load_meta")
      @stats.merge(@file["load_meta"]) {|key, a_val, b_val| a_val.merge b_val }
    end

  end

  def firmware
    @firmware_id = params[:id]
    @objects = []

    ### Section firmware type
    @firmware_type = ""
    cursor = r.db("uefi").table("updates").filter{|obj| obj["firmware_id"].eq(@firmware_id)}.
      pluck("type").run
    cursor.each do |obj|
      @firmware_type = obj["type"]
      break
    end

    cursor = r.db("uefi").table("objects").filter{|obj| obj["firmware_id"].eq(@firmware_id)}.
      pluck("attrs", "guid", "object_id", "load_meta").
      order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run

    cursor.each do |obj|
      ### Todo: handle each type of firmware, populate obj["objects"]
      obj["objects"] = []
      add_lookups!(obj)

      obj["stats"] = {}
      objects_count = r.db("uefi").table("objects").count{|_obj| _obj["firmware_id"].eq(obj["object_id"])}.run
      files_count = r.db("uefi").table("files").count{|_obj| _obj["firmware_id"].eq(obj["object_id"])}.run
      if objects_count > 0 then obj["stats"]["Objects"] = objects_count end
      if files_count > 0 then obj["stats"]["UEFI Files"] = files_count end

      @objects.push(obj)
    end

  end

  def uefi
    @firmware_id = params[:id]
    @files = []

    ### Search for objects, later bind them to each file listed.
    objects = {}
    cursor = r.db("uefi").table("objects").filter{|obj| obj["firmware_id"].eq(@firmware_id)}.
      pluck("attrs", "guid", "load_meta").
      order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run
    cursor.each do |obj|
      unless objects.has_key? (obj["guid"])
        objects[obj["guid"]] = []
      end
      objects[obj["guid"]].push(obj)
    end

    ### Finally, search for files belonging to this firmware_id
    cursor = r.db("uefi").table("files").filter{|file| file["firmware_id"].eq(@firmware_id)}.
      pluck("name", "guid", "description", "attrs", "load_change", "size").
      order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run
    cursor.each do |file|
      if objects.has_key? (file["guid"])
        file["objects"] = objects[file["guid"]]
      else
        file["objects"] = []
      end

      add_lookups!(file)
      
      ### Add an assortment of stats
      if file.has_key? ("load_change")
        file["stats"] = {}
        if file["load_change"].has_key? ("change_score") and file["load_change"]["change_score"] > 0
          file["stats"]["Changed"] = "%d bytes, %.2f%" % [file["load_change"]["change_score"], percent_change(file)]
        end
        if file["load_change"].has_key? ("new_file")
          file["stats"]["New File"] = true
        end
      end

      @files.push(file)
    end


  end

private
  def db_connect
  	r.connect(:host => "localhost").repl
  end

  def percent_change (_obj)
    size = _obj.has_key?("size") ? _obj["size"] : _obj["attrs"]["size"]
    score = _obj["load_change"]["change_score"]
    return (score/(size * 1.0))*100
  end

  def lookups
    if @lookups != nil
      return @lookups
    end

    ### Search for optional lookup values which better describe each file
    @lookups = {}
    cursor = r.db("uefi").table("lookup").run
    cursor.each do |lookup|
      @lookups[lookup["guid"]] = lookup
    end
    return @lookups
  end

  def add_lookups! (_obj)
    lookups = lookups()
    if lookups.has_key?(_obj["guid"])
      lookups[_obj["guid"]].each do |key, value|
        next if key == "guid"
        _obj[key] = "*%s" % value
      end
    end
  end

end