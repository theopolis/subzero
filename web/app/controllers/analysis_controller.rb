require 'rethinkdb'

### Remove later, abstract DB accesses to DbController
include RethinkDB::Shortcuts

class AnalysisController < DbController
  before_filter :db_connect
  helper_method :menu_items

  def menu_items
    [
      ['GUIDs', "/analysis/guids"],
      ["Keywords", "/analysis/keywords"],
      ["Vulns", "/analysis/vulnerabilities"],
      ["Potential Vulns", "/analysis/similarities"],
      ["Capsule Data", "/analysis/capsules"]
    ]
  end

  def analysis
    select_limit = 5
    ### Most uses GUIDS
    @guids = []
    cursor = @stats_table.get_all("uefi_guid", :index => "type").order_by(r.desc(:result)).limit(select_limit).
    map{|doc|
      doc.merge({
        "lookup" => @lookup_table.get_all(doc[:key], :index => "guid").coerce_to("array")
    })}.run
    cursor.each{|guid| @guids.push(flatten_lookup(guid))}

    ### Largest guids
    @guids_size = []
    cursor = @objects_table.order_by(:index => r.desc(:size)).has_fields(:guid).pluck(:guid, :size).
      limit(select_limit).
        map{|doc|
          doc.merge({
            "lookup" => @lookup_table.get_all(doc[:guid], :index => "guid").coerce_to("array")
        })}.run
    cursor.each {|guid| @guids_size.push(flatten_lookup(guid))}

    ### Fastest updates, calculate the change in updates
    @fast_updates = []
    cursor = @updates_table.filter{|doc| doc[:load_change][:delta] > 0}.
      order_by(lambda {|doc| doc[:load_change][:delta]}).limit(select_limit).run
    cursor.each {|update| @fast_updates.push(update)}

    ### Smallest updates, order by asc load_change->change
    @small_updates = []
    cursor = @updates_table.filter{|doc| doc[:load_change][:change_score] > 0}.
      order_by(lambda {|doc| doc[:load_change][:change_score]}).limit(select_limit).run
    cursor.each {|update| @small_updates.push(update)}

    ### Most common DXE
    @dxes = []

    ### Most common PEIMs
    @peims = []


  end

  def keywords
    ### Importantce != Optional (Dell)
    not_importances = ["Optional", "Recommended"]
    @updates = []
    cursor = @updates_table.filter{|update|
      update[:attrs][:importance].eq("Urgent") | update[:attrs][:importance].eq("Required") |
      update[:attrs][:importance].eq("Critical")
    }.order_by(:date).order_by(:vendor).run
    cursor.each {|update| 
      @updates.push(update_dict(update))
    }
    puts @updates.length

    ### Trusted-compusing GUIDs
    ### (lookup-> important(reason->trusted,security,vulnerable), references, [optional]key)
    ### (objects-> actions[trusted])

    ### Release notes with security, vulnerability, exploit

  end

  def similarities
    ### Assembly with function calls (CopyMem)

  end

  def vulnerabilities
    ### Updates identified as being a vulnerability fix 
    ### (update-> patch(notes, references, [optional]key))
    ### (objects-> actions[vulnerable])

    ### FW PEIMs/DXEs using the network

    ### Changes to high-profile GUIDs (and trusted computing, update-related GUIDs)

  end

  def trusted
    ### List guids related to trusted computing/secure boot/key storage
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

    @guids.sort! { |guid1, guid2| guid1[:count] <=> guid2[:count]}
    @guids.reverse!
    puts @guids.length
  end

  def guid
    @guid = params[:id]
    @objects = []
    cursor = object_query(@objects_table.get_all(@guid, :index => "guid").
      ### TESTING
      order_by(:size).limit(20)
      ).run
    cursor.each do |obj|
      @objects.push(get_object_info(obj))
    end

    @objects = @objects.paginate(:page => params[:page], :per_page => 30)

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