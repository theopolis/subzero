require 'rethinkdb'
require "base64"

include RethinkDB::Shortcuts

class ExplorerController < ApplicationController
  before_filter :db_connect

  #def initialize
  #  @PER_PAGE = 30
  #end

  def sort_direction
    %w[asc desc].include?(params[:direction]) ? params[:direction] : "asc"
  end

  def explorer
    ### There is nothing on this page for now

  end

  def products
    @page_num = if params.has_key?(:page) then params[:page].to_i-1 else 0 end
    @products = {}
    ### Iterate the updates and count the number per machine
    updates = r.db("uefi").table("updates").
      order_by(:index => r.desc(:date)).
      pluck("version", "products", "date", "vendor", "item_id", 
        "attrs", "name", "firmware_id", "size", "load_change").run
    ### Do sorting here

    updates.each do |doc|
      doc["products"].each do |product|
        unless @products.has_key?(product)
          @products[product] = []
        end
        ### Add the version/date/vendor
        add_object_stats!(doc, false)
        @products[product].push({
          :name => doc["name"], 
          :version => doc["version"], 
          :date => doc["date"], 
          :vendor => doc["vendor"], 
          :item_id => doc["item_id"],
          :firmware_id => doc["firmware_id"],
          :size => doc["size"],
          :status => doc["attrs"]["status"],
          :load_change => if doc.has_key?("load_change") then doc["load_change"] else {} end,
          :stats => doc["stats"]
        })
      end
    end
    
    @products_keys = @products.keys.paginate(:page => params[:page], :per_page => 60)
    ### Leave counting/stats up to the viewer.
  end

  def sort_product_column
    keys = ["date", "name", "size"]
    #Product.column_names.include?(params[:sort]) ? params[:sort] : "name"
  end

  def download
    @object_id = params[:object_id]

    object = r.db("uefi").table("objects").get(@object_id).run
    if object == nil
      return
    end

    send_data Base64.decode64(object["content"]), 
      :filename => "%s-%s.obj" % [object["firmware_id"], object["guid"]]
  end

  def raw
    @firmware_id = params[:firmware_id]
    @id = params[:id]    

    ### Get Information about object
    cursor = r.db("uefi").table("objects").get_all(@firmware_id, :index => "firmware_id").
      filter{|obj| obj["id"].eq(@id)}.
      pluck("name", "guid", "description", "attrs", "load_change", "size", "id", "load_meta").limit(1).run

    ### Silly construct
    cursor.each{ |obj| @object = obj }
    add_object_stats!(@object)
  end

  def file
    @firmware_id = params[:firmware_id]
    @guid = params[:id]

    ### Get Information about File
    cursor = r.db("uefi").table("objects").get_all(@firmware_id, :index => "firmware_id").
      filter{|file|  file["guid"].eq(@guid) }.
      pluck("name", "guid", "description", "attrs", "load_change", "size").limit(1).run

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
    @depth = 1
    @object_id = params[:id]
    @firmware_id = "None"
    @firmware_object = {}

    ### Get the base firmware object
    cursor = @objects_table.get_all(@object_id, :index => "object_id").eq_join(
      'firmware_id', @updates_table, :index => "firmware_id"
      ).order_by(r.desc(lambda {|doc| doc[:size]})).limit(1).zip.run

    cursor.each do |obj|
      @firmware_id = obj["firmware_id"]
      @firmware_object = get_object_info(obj)
    end

    ### Keep a hash of child_id -> object id
    child_map = {}
    child_ids = @firmware_object["children"].dup
    child_ids.each {|id| child_map[id] = @firmware_object}
    @firmware_object["objects"] = []

    ### Embedded object may paginate better
    if @firmware_object["firmware_id"] != @firmware_object["object_id"]
      @depth += 1
    end

    ### Get the children objects
    depth_index = 0
    while child_ids.length > 0 and depth_index < @depth
      depth_index += 1
      cursor = @objects_table.get_all(*child_ids).
        map{|doc|
          r.branch(
            doc.has_fields([:guid]),
            doc.merge({
              ### Add in map-reduces
              "shared" => @stats_table.get_all(["uefi_guid", doc[:guid]], :index => "type_key").pluck("result").coerce_to('array'),
              "matches" => @stats_table.get_all(["object_id", doc[:object_id]], :index => "type_key").pluck("result").coerce_to('array'),
              "lookup" => @lookup_table.get_all(doc[:guid], :index => "guid").coerce_to("array")
            }),
            doc.merge({})
        )}.map{|doc|
          doc.merge({
            "content" => @content_table.get_all(doc["object_id"], :index => "object_id").pluck("attrs", "load_meta").coerce_to("array")
        })}.order_by(r.desc(lambda {|doc| doc[:size]})).run

      child_ids = []
      cursor.each do |obj|
        ### Add this object to it's parent
        obj["objects"] = []
        child_map[obj["id"]]["objects"].push(get_object_info(obj))
        #@objects.push(get_object_info(obj))
        if obj.has_key?("children")
          obj["children"].each{|id| child_map[id] = obj}
          child_ids = child_ids.concat(obj["children"].dup)
        end
      end
    end

    @objects = @firmware_object["objects"]
    @objects = @objects.paginate(:page => params[:page], :per_page => 30)

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
    @db = r.db("uefi")
    @objects_table = r.db("uefi").table("objects")
    @stats_table   = r.db("uefi").table("stats")
    @updates_table = r.db("uefi").table("updates")
    @content_table = r.db("uefi").table("content")
    @lookup_table  = r.db("uefi").table("lookup")
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
    unless objects_count == 0
      _obj["stats"]["Children"] = objects_count
    end

    ### Handle various lookups data from lookup table
    if _obj.has_key?("lookup") and _obj["lookup"].length > 0
      if _obj["lookup"][0].has_key?("guid_name") then _obj["guid_name"] = _obj["lookup"][0]["guid_name"] end
    end

    unless _obj.has_key?("attrs")
      _obj["attrs"] = {}
    end

    if _obj["type"] == "uefi_file"
      _obj["info"] = {
        #"Attrs" => _obj["attrs"]["attributes"],
        "FileType" => _obj["attrs"]["type_name"],
      }

      ### Requires a map-reduce
      unless _obj["shared"].length == 0
        _obj["stats"]["Shared"] = _obj["shared"][0]["result"]
      end
      unless _obj["matches"].length == 0
        _obj["stats"]["Matches"] = _obj["matches"][0]["result"]
      end

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