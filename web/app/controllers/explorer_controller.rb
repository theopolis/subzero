require 'rethinkdb'
require "base64"

### Remove later, abstract DB accesses to DbController
include RethinkDB::Shortcuts

class ExplorerController < DbController
  before_filter :db_connect

  #def initialize
  #  @PER_PAGE = 30
  #end

  def sort_direction
    %w[asc desc].include?(params[:direction]) ? params[:direction] : "asc"
  end

  def explorer
    ### There is nothing on this page for now
    @vendors = []
    cursor = @stats_table.get_all("vendor_update_count", :index => "type").run
    cursor.each {|vendor| @vendors.push({:name => vendor["key"], :count => vendor["result"]})}

  end

  def products
    @vendor = params[:vendor]
    @page_num = if params.has_key?(:page) then params[:page].to_i-1 else 0 end
    @products = {}
    ### Iterate the updates and count the number per machine
    updates = r.db("uefi").table("updates").get_all(@vendor, :index => "vendor").
      order_by(r.desc(:date)).
      #pluck("version", "products", "date", "vendor", "item_id", 
      #  "attrs", "name", "firmware_id", "size", "load_change").
      run
    ### Do sorting here

    updates.each do |doc|
      doc["products"].each do |product|
        unless @products.has_key?(product)
          @products[product] = []
        end
        ### Add the version/date/vendor
        add_object_stats!(doc, false)
        @products[product].push(update_dict(doc))
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
    ### Todo: pluck from updates: .pluck("date", "attrs", "item_id", "name", "vendor", "version")
    cursor = @objects_table.get_all(@object_id, :index => "object_id").eq_join(
      'firmware_id', @updates_table, :index => "firmware_id"
      ).order_by(r.desc(lambda {|doc| doc[:size]})).limit(1).run

    cursor.each do |obj|
      obj["right"].each do |key, value|
        if not ["load_meta", "load_change"].include?(key) then obj["left"][key] = value end
      end
      puts obj["left"]["firmware_id"]
      @firmware_id = obj["left"]["firmware_id"]
      @firmware_object = get_object_info(obj["left"])
    end

    ### Keep a hash of child_id -> object id
    child_map = {}
    child_ids = []
    if @firmware_object.has_key? ("children")
      child_ids = @firmware_object["children"].dup
      child_ids.each {|id| child_map[id] = @firmware_object}
    end
    @firmware_object["objects"] = []

    ### Embedded object may paginate better
    if @firmware_object["firmware_id"] != @firmware_object["object_id"] then @depth += 1 end

    ### Get the children objects
    depth_index = 0
    while child_ids.length > 0 and depth_index < @depth
      depth_index += 1
      cursor = @objects_table.get_all(*child_ids).
        #### TESTING
        limit(20).
        #### END TESTING
        map{|doc| r.branch(doc.has_fields([:guid]), doc.merge({
          ### Add in map-reduces
          "shared" => @stats_table.get_all(["uefi_guid", doc[:guid]], :index => "type_key").pluck("result").coerce_to('array'),
          "matches" => @stats_table.get_all(["object_id", doc[:object_id]], :index => "type_key").pluck("result").coerce_to('array'),
          "lookup" => @lookup_table.get_all(doc[:guid], :index => "guid").coerce_to("array")
        }), doc.merge({})
      )}.map{|doc|doc.merge({
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

    @changed = []
    @objects = @firmware_object["objects"]
    @objects.each do |obj|
      if obj.has_key?("load_change") and obj["load_change"]["change_score"] > 32
        @changed.push(obj)
      end
    end

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

  def actions
    ### Set on an object, and push to the update (use firmware_id as reference)
    ### {actions/guid_actions => {vulnerable, trusted, network}} # all booleans (then can look backwards)
    ### vulnerable implies this update has fixed a vulnerability, so the most-recent compartively
    ### will be marked vulnerable (and cannot be changed)
    @name = params[:name]
    @value = params[:actions][:value]
    @object_id = params[:actions][:id]
    @firmware_id = params[:actions][:firmware_id]

    success = true
    unless @value == "locked"
      new_value = @value == "true" ? "false" : "true"
      if @name == "vulnerable"
        @objects_table.get(@object_id).update({"actions" => {"vulnerable" => new_value}}).run
        cursor = @updates_table.get_all(@firmware_id, :index=> "firmware_id").run
        firmware_update = nil
        cursor.each{ |update| firmware_update = update}
        if firmware_update != nil
          actions = firmware_update.has_key?("actions") ? firmware_update["actions"] : {"vulnerable" => []}
          if new_value == "true" and not actions["vulnerable"].include?(@object_id)
            actions["vulnerable"].push(@object_id)
          elsif new_value == "false" and actions["vulnerable"].include?(@object_id)
            actions["vulnerable"] = actions["vulnerable"] - [@object_id]
          end
          @updates_table.get(firmware_update["id"]).update({"actions" => actions}).run
          puts actions
        end
      end

      if @name == "trusted" or @name == "network"
        object_data = @objects_table.get(@object_id).run
        if object_data.has_key? ("guid")
          guid = nil
          cursor = @lookup_table.get_all(object_data["guid"], :index => "guid").run
          cursor.each {|doc| guid = doc}
          if guid != nil
            actions = guid.has_key?("actions") ? guid["guid_actions"] : {}
            actions[@name] = new_value
            @lookup_table.get(guid["id"]).update({"guid_actions" => actions}).run
            puts guid["id"]
          else
            @lookup_table.insert({"guid" => object_data["guid"], "guid_actions" => {@name => new_value}}).run
          end
        end
        #cursor = @lookup_table.get_all()
      end

    end

    respond_to do |format|
      format.json { render :json => { 
        :success => success, 
        :value => new_value,

        :type => @name,
        :previous => @value,
        :id => @object_id 
      } }
    end
  end


end