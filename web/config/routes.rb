RailsBootstrap::Application.routes.draw do
  root :to => 'visitors#new'

  get 'explorer' => "explorer#explorer"
  get 'explorer/uefi/:id' => "explorer#uefi"
  get 'explorer/firmware/:id' => "explorer#firmware"

  get 'explorer/file/:firmware_id/:id' => "explorer#file"
  get 'explorer/download/:object_id' => "explorer#download"
end
