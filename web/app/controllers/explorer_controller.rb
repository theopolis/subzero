require 'rethinkdb'
require "base64"

include RethinkDB::Shortcuts

class ExplorerController < ApplicationController
  before_filter :db_connect

  def explorer
    ### There is nothing on this page for now
  end

  def products
    @products = {}
    ### Iterate the updates and count the number per machine
    updates = r.db("uefi").table("updates").
      pluck("version", "products", "date", "vendor", "item_id", "attrs", "name", "firmware_id", "size").
      order_by(r.asc(lambda {|doc| doc[:date]})).run
    updates.each do |doc|
      doc["products"].each do |product|
        unless @products.has_key?(product)
          @products[product] = []
        end
        ### Add the version/date/vendor
        @products[product].push({
          :name => doc["name"], 
          :version => doc["version"], 
          :date => doc["date"], 
          :vendor => doc["vendor"], 
          :item_id => doc["item_id"],
          :firmware_id => doc["firmware_id"],
          :size => doc["size"],
          :status => doc["attrs"]["status"]
        })
      end
    end
    ### Leave counting/stats up to the viewer.
  end

  # GET /explorer
  def explorer_old
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

  def raw
    @firmware_id = params[:firmware_id]
    @id = params[:id]    

    ### Get Information about object
    cursor = r.db("uefi").table("objects").filter{|obj| 
        (obj["firmware_id"].eq(@firmware_id)) & (obj["id"].eq(@id))
      }.pluck("name", "guid", "description", "attrs", "load_change", "size", "id", "load_meta").limit(1).run

    ### Silly construct
    cursor.each{ |obj| @object = obj }
    add_object_stats!(@object)
  end

  def file
    @firmware_id = params[:firmware_id]
    @guid = params[:id]

    ### Get Information about File
    cursor = r.db("uefi").table("files").filter{|file| 
        (file["firmware_id"].eq(@firmware_id)) & (file["guid"].eq(@guid))
      }.pluck("name", "guid", "description", "attrs", "load_change", "size").limit(1).run

    ### Silly construct
    cursor.each{ |file| @file = file }

    ### Stats will display a table of key=>value details
    @stats = {
      "name" => @file.has_key?("name") ? @file["name"] : "",
      "description" => @file.has_key?("description") ? @file["description"] : "",
    }
    @stats = @stats.deep_merge(@file["attrs"])

    ### Collect objects within this file
    @objects = []
    cursor = r.db("uefi").table("objects").filter{|obj| 
        (obj["firmware_id"].eq(@firmware_id)) & (obj["guid"].eq(@guid))
      }.pluck("attrs", "load_meta", "load_change", "id").
      order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run

    cursor.each do |obj|
      add_object_stats!(obj)
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
      pluck("attrs", "guid", "object_id", "id", "load_meta", "load_change").
      order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run

    cursor.each do |obj|
      ### Todo: handle each type of firmware, populate obj["objects"]
      obj["objects"] = []
      add_lookups!(obj)
      add_object_stats!(obj, attrs = false, meta = false)

      ### This is a different type of stats
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
      add_object_stats!(file, attrs = false, meta = false)
      @files.push(file)
    end

  end

private
  def db_connect
  	r.connect(:host => "localhost").repl
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
    if meta and obj.has_key?("load_meta") then obj["stats"] = obj["stats"].merge(obj["load_meta"]) end

    if obj.has_key? ("load_change")
      if obj["load_change"].has_key? ("change_score") and obj["load_change"]["change_score"] > 0
        obj["stats"]["Changed"] = "%d bytes, %.2f%" % [obj["load_change"]["change_score"], percent_change(obj)]
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

end