# remove comments and default routes from routes.rb
file "config/routes.rb", "#{app_const}.routes.draw do\nend"
git :add => ".", :commit => "-m 'remove comments and default routes from routes.rb.'"
