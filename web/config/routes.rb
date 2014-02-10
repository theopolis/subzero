RailsBootstrap::Application.routes.draw do
  root :to => 'visitors#new'

  get 'explorer' => "explorer#explorer"
  get 'explorer/firmware/:id' => "explorer#firmware"

  get 'explorer/file/:firmware_id/:id' => "explorer#file"
end
