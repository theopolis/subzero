require 'rethinkdb'

### Remove later, abstract DB accesses to DbController
include RethinkDB::Shortcuts

class AnalysisController < DbController
  before_filter :db_connect

  def analysis
    ### Most uses GUIDS
    @guids = []
    cursor = @stats_table.get_all("uefi_guid", :index => "type").order_by(r.desc(:result)).limit(5).
    map{|doc|
      doc.merge({
        "lookup" => @lookup_table.get_all(doc[:key], :index => "guid").coerce_to("array")
    })}.run
    cursor.each{|guid| @guids.push(flatten_lookup(guid))}

    ### Largest guids
    @guids_size = []
    cursor = @objects_table.order_by(:index => r.desc(:size)).has_fields(:guid).pluck(:guid, :size).limit(5).
    map{|doc|
      doc.merge({
        "lookup" => @lookup_table.get_all(doc[:guid], :index => "guid").coerce_to("array")
    })}.run
    cursor.each {|guid| @guids_size.push(flatten_lookup(guid))}

    ### Fastest updates, calculate the change in updates

    ### Smallest updates, order by asc load_change->change

    ### Most common DXE

    ### Most common PEIMs

  end

  def keywords
    ### Importantce != Optional (Dell)
    not_importances = ["Optional", "Recommended"]
    @updates = []
    cursor = @updates_table.filter{|update|
      update[:attrs][:importance].eq("Urgent") | update[:attrs][:importance].eq("Required")
    }.run
    cursor.each {|update| 
      @updates.push(update_dict(update))
    }
    puts @updates.length

    ### Trusted-compusing GUIDs

    ### Release notes with security, vulnerability, exploit

  end

  def similarities
    ### Assembly with function calls (CopyMem)

  end

  def vulnerabilities
    ### Updates identified as being a vulnerability fix

    ### FW PEIMs/DXEs using the network

    ### Changes to high-profile GUIDs (and trusted computing, update-related GUIDs)


  end

  def guids
    @guids = []
    cursor = @stats_table.get_all("uefi_guid", :index => "type").map{|doc|
      doc.merge({
        "lookup" => @lookup_table.get_all(doc[:key], :index => "guid").coerce_to("array")
        })
      }.run
    cursor.each do |lookup|
      lookup = flatten_lookup(lookup)
      @guids.push({
        :guid => lookup["key"], 
        :name => lookup["guid_name"],
        :count => lookup["result"]
      })
    end

    puts @guids.length
  end

  def guid
    @guid = params[:id]
    @objects = []
    cursor = object_query(@objects_table.get_all(@guid, :index => "guid")).run
    cursor.each do |obj|
      @objects.push(get_object_info(obj))
    end

  end

  private
    def flatten_lookup(obj)
      blacklist = ["guid", "id"]
      if obj.has_key?("lookup") and obj["lookup"].length > 0
        obj["lookup"][0].each do |key, value|
          next if blacklist.include?(key)
          obj[key] = value
        end
      end
      return obj
    end

end