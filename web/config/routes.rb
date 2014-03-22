RailsBootstrap::Application.routes.draw do
  ### Maybe have graphs here?
  root :to => 'explorer#search'

  ### List of all machines or graphs?
  get 'explorer' => "explorer#explorer"

  ### Machines/ISV/OEM views
  get 'explorer/products' => "explorer#products"
  get 'explorer/vendors' => "explorer#vendors"
  get 'explorer/objects' => "explorer#objects"
  get 'explorer/vendor/:name' => "explorer#vendor"
  get 'explorer/machine/:id' => "explorer#machine"

  ### Object views
  get 'explorer/uefi/:id' => "explorer#uefi"
  get 'explorer/firmware/:id' => "explorer#firmware"

  ### Downloads
  get 'explorer/file/:firmware_id/:id' => "explorer#file"
  get 'explorer/raw/:firmware_id/:id' => "explorer#raw"

  get 'explorer/download/:object_id' => "explorer#download"
end
