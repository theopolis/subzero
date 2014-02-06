require 'rethinkdb'
include RethinkDB::Shortcuts

class ExplorerController < ApplicationController
  before_filter :db_connect

  # GET /explorer
  def explorer
  	@firmware = []

  	updates = r.db("uefi").table("updates").
      order_by(r.asc(lambda {|doc| doc[:version]})).run
  	updates.each do |doc|
  	  p doc
  	  @firmware.push(doc)
  	end
  end

  def firmware
    firmware_id = params[:id]
    @files = []

    objects = {}
    cursor = r.db("uefi").table("objects").filter{|obj| obj["firmware_id"].eq(firmware_id)}.
      pluck("attrs", "guid", "load_meta").
      order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run
    cursor.each do |obj|
      unless objects.has_key? (obj["guid"])
        objects[obj["guid"]] = []
      end
      objects[obj["guid"]].push(obj)
    end

    cursor = r.db("uefi").table("files").filter{|file| file["firmware_id"].eq(firmware_id)}.
      pluck("name", "guid", "description", "attrs").
      order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run
    cursor.each do |file|
      #p file["guid"]
      #child_cursor = r.db("uefi").table("objects").filter{|obj| obj["guid"].eq(file["guid"])}.
      #  pluck("attrs").
      #  order_by(r.desc(lambda {|doc| doc[:attrs][:size]})).run
      if objects.has_key? (file["guid"])
        file["objects"] = objects[file["guid"]]
      else
        file["objects"] = []
      end
      #child_cursor.each{|child| file["objects"].push(child)}
      @files.push(file)
    end


  end

private
  def db_connect
  	r.connect(:host => "localhost").repl
  end


end