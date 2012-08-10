# Brian Morearty's template for Rails apps
#
# Features:
# - Creates a .gitignore file
# - Capifies
# - Does rake gems:build during cap deploy
# - Optionally adds resque for background jobs
#   - If resque is added, adds helper scripts resque, resque-web, and resque-workers.
#     Also stops resque workers temporarily during deploy, restarts when done deploying.
# - Adds will_paginate
# - Adds hash_mapper
# - Adds aegis (permissions) and creates a default permissions file with :guest, :registered, and :admin roles
#   - Adds an assign_role rake task to assign a role to a user
# - Adds authlogic
#   - Creates a UserSessionsController
#   - Creates a login page and a sign up page
#   - Sets up login and logout and signup routes
#   - Creates a user model, including authlogic's magic fields
# - Adds refraction for redirects
# - Adds connection_fix.rb in case the MySQL connection times out
# - Adds jQuery.  Removes Prototype.
# - Adds jrails for jQuery integration
# - Adds eztime for better formatted output of dates and times
# - Adds query_trace for showing stack dumps during SQL calls
# - Adds admin_data for easy and powerful administration pages
# - Adds shoulda to test_helper
# - Adds a home page and puts it in the routes
# - Adds an application-wide layout
# - Filters sensitive parameters in the log
# - Specifies the use of sql instead of schema dumper when creating the test database,
#   to support constraints or schema changes written in SQL.
# - Adds yui-reset, yui-base, and yui-font, and some application-level default css
#
# Usage:
#   rails -d mysql -m brians_template.rb my_app_name

require File.join(File.dirname(__FILE__), 'core_extensions.rb')

# Ask questions up front

# If not using git, set up git :rm to just remove the file without git
if no?("Are you using git?")
  def git(first, *rest)
    case
    when Hash === first && first[:rm] then run "rm #{first[:rm]}"
    end
  end
end

# Like gsub_file_with_match_check but raises an error if no matches were found.
#
# ==== Example
#
#   gsub_file_with_match_check 'app/controllers/application_controller.rb', /#\s*(filter_parameter_logging :password)/, '\1'
#
def gsub_file_with_match_check(relative_destination, regexp, *args, &block)
  path = destination_path(relative_destination)
  matches = File.read(path).match(regexp)
  raise "Regexp not found in #{relative_destination}\n called from #{caller.first}" unless matches
  gsub_file(relative_destination, regexp, *args, &block)
end

include_resque = yes?("Will you use Resque for background jobs?")
jquery_default = "1.4.1"
jquery_ver = ask "What version of jQuery do you want? [default is #{jquery_default}]"
jquery_ver = jquery_default if jquery_ver.blank?

apply recipe("gitignore")
apply recipe("initial_commit")
apply recipe("cleanup_routes")
apply recipe("capify")  # has to be before appending to config/deploy.rb
apply recipe("add_build_gems_deploy_task")

# UP TO HERE...

return



# gems are in reverse order from how I'd like them to end up

if include_resque
  # Next 3 are for redis
  gem "sinatra", :lib => false
  gem "vegas", :lib => false
  gem "rspec", :lib => false
  # Next 4 are for Resque
  gem "resque"  # Resque must be installed on the machine to run resque-web
  gem "redis"
  gem "redis-namespace", :lib => false
  gem "yajl-ruby", :lib => "yajl"

  file "script/resque",
%q{#!/usr/bin/env ruby
#
# This just runs the resque command in vendor/gems/resque
exec File.dirname(__FILE__) + "/runner " + Dir.glob(File.dirname(__FILE__) + '/../vendor/gems/resque-*').first + '/bin/resque ' + $*.join(" ")
}

  file "script/resque-web",
%q{#!/usr/bin/env ruby
exec Dir.glob(File.dirname(__FILE__) + '/../vendor/gems/resque-*').first + '/bin/resque-web'
}

  file "script/resque-workers",
%q{#!/usr/bin/env ruby

# Start or stop the resque worker.
#
# script/resque-workers start    Starts the workers (currently there's just one).
#                                Writes its pid to tmp/pids/resque-worker.pid under RAILS_ROOT.
# script/resque-workers stop     Stops the workers.  Deletes tmp/pids/resque-worker.pid.
#
# Pass RAILS_ENV=production on the comnmand line to specify an environment.

pidfile = File.dirname(__FILE__) + "/../tmp/pids/resque-worker.pid"

case ARGV[0]
when "start"
  Dir.chdir File.dirname(__FILE__) + "/.."
  fork do
    # RAILS_ENV is passed to the child process automatically
    IO.popen("rake environment resque:work QUEUES=find_replies,send_mail") do |pipe|
      File.open(pidfile, "w") do |f|
        puts "pid is #{pipe.pid}"
        f.write pipe.pid
      end
    end
  end
  sleep 2 # wait for the subprocess to write to the pidfile--seems to be required in Capistrano
  puts "exiting"
when "stop"
  if File.exist?(pidfile)
    begin
      # Wait for child worker to exit, then quit
      %x{kill -s QUIT `cat #{pidfile}`}
    ensure
      File.delete pidfile
    end
  end
end}

  append_file "config/deploy.rb", '

# Stop background workers for resque.  Delete the tmp file that held the process id.
task :stop_resque_workers do
  run "#{sudo} monit stop resque-workers"
end
before "deploy:update_code", :stop_resque_workers
before "deploy:rollback", :stop_resque_workers

# Start background workers for resque.  Store the process id in /tmp/resque-worker.pid
task :start_resque_workers do
  run "#{sudo} monit start resque-workers"
end
after "deploy", :start_resque_workers
after "deploy:rollback", :start_resque_workers
'

  run "chmod +x script/resque script/resque-web script/resque-workers"

  file "config/initializers/load_resque.rb", "require 'resque'"

  git :add => ".", :commit => "-m 'add resque.'"
end

gem "jrails"        # jquery replacement for prototype helpers
gem "will_paginate" # pagination
gem "hash_mapper"   # map hash attributes
gem "aegis"         # permissions
git :add => ".", :commit => "-m 'add more gems.'"

# authlogic generator
gem "authlogic"     # user logins
generate :session, "user_session"  # creates app/models/user_session.rb
generate :controller, "user_sessions" # create controller, tests, etc. 
gsub_file_with_match_check "app/controllers/user_sessions_controller.rb", /^end$/,
  %q{

  before_filter :must_be_able_to_log_out, :only => [ :destroy ]
  before_filter :must_be_able_to_log_in, :only => [ :new, :create ]

  def new
    @user_session = UserSession.new
  end

  def create
    reset_session # prevent session fixation - http://guides.rubyonrails.org/security.html
    @user_session = UserSession.new(params[:user_session])
    if @user_session.save
      flash[:notice] = "Successfully logged in."
      cookies[:username] = { :value => current_user(true).username, :expires => 10.years.from_now }
      redirect_to root_url
    else
      render :action => 'new'
    end
  end

  def destroy
    @user_session = UserSession.find
    @user_session.destroy
    cookies.delete :username
    flash[:notice] = "Successfully logged out."
    redirect_to root_url
  end

private

  def must_be_able_to_log_out
    if !current_user.may_logout?
      flash[:notice] = "You're already logged out"
      redirect_to root_path
    end
  end

  def must_be_able_to_log_in
    if !current_user.may_login?
      flash[:notice] = "You're already logged in"
      redirect_to root_path
    end
  end
end
}

file "config/locales/en.yml", <<-END
en:
  activerecord:
    models:
      user: Account            # Create/edit account page button is "Create Account"/"Update Account"
  error_messages:
    login_invalid: should be letters, numbers, dashes, and underscores, please (starting with a letter)
END

file "app/views/user_sessions/new.html.erb", <<-END
<% title "Login" %>

<% semantic_form_for @user_session do |f| %>
  <%= f.inputs :username, :password, :class => "hide-required vertical" %>
  <%= f.buttons :class => "vertical" %>
<% end %>

<%= javascript_tag "$('#user_session_username').focus();"  %>
END
git :add => ".", :commit => "-m 'add Login page.'"

# TODO: support the "current" ID for user actions.  Then add this route:
# route %Q{map.edit_account "edit-account", :controller => "users", :action => "edit", :id => "current"}
route %Q{map.signup "signup", :controller => "users", :action => "new"}
route %Q{map.logout "logout", :controller => "user_sessions", :action => "destroy"}
route %Q{map.login "login", :controller => "user_sessions", :action => "new"}
route %Q{map.resources :user_sessions, :only => [ :new, :create, :destroy ]}
git :add => ".", :commit => "-m 'add login and logout and user_session routes.'"

# create user model, including authlogic's magic fields
user_attrs = [
  { :name => "username",              :type => "string",  :constraints => { :null => false } },
  { :name => "email",                 :type => "string",  :constraints => { :null => false } },
  { :name => "role_name",             :type => "string",  :constraints => { :null => false } },
  { :name => "crypted_password",      :type => "string",  :constraints => { :null => false } },
  { :name => "password_salt",         :type => "string",  :constraints => { :null => false } },
  { :name => "persistence_token",     :type => "string",  :constraints => { :null => false } },
  { :name => "single_access_token",   :type => "string",  :constraints => { :null => false } },
  { :name => "perishable_token",      :type => "string",  :constraints => { :null => false } },
  { :name => "login_count",           :type => "integer", :constraints => { :null => false, :default => 0 } },
  { :name => "failed_login_count",    :type => "integer", :constraints => { :null => false, :default => 0 } },
  { :name => "last_request_at",       :type => "datetime" },
  { :name => "current_login_at",      :type => "datetime" },
  { :name => "last_login_at",         :type => "datetime" },
  { :name => "current_login_ip",      :type => "string" },
  { :name => "last_login_ip",         :type => "string" }
]
generate :scaffold, %{User #{user_attrs.map {|attr| "#{attr[:name]}:#{attr[:type]}"}.join(" ")}}
# remove users scaffold layout
git :rm => "app/views/layouts/users.html.erb"
# remove :index action
sentinel = 'map.resources :users'
gsub_file_with_match_check "config/routes.rb", /(#{Regexp.escape(sentinel)})/mi, "map.resources :users, :except => [ :index ]"
sentinel = %r{  # GET /users\n.+end\n\s+end\s+(  # GET /users/1\n)}mi
gsub_file_with_match_check "app/controllers/users_controller.rb", sentinel do |match|
  $1
end
sentinel = <<-END
  test "should get index" do
    get :index
    assert_response :success
    assert_not_nil assigns(:users)
  end
END
gsub_file_with_match_check "test/functional/users_controller_test.rb", /(#{Regexp.escape(sentinel)})/mi, <<-END
  test "should not get index" do
    assert_raise ActionController::RoutingError do
      get :index
    end
  end
END
git :rm => "app/views/users/index.html.erb"
file "app/views/users/_form.html.erb", <<-END
<% semantic_form_for @user do |f| %>
  <%= f.inputs :username, :email, :password, :password_confirmation %>
  <%= f.buttons %>
<% end %>
END
file "app/views/users/new.html.erb", <<-END
<% title "Sign Up" %>

<h1><%= yield :title %></h1>
<%= render :partial => "form" %>
END
file "app/views/users/edit.html.erb", <<-END
<% title "Edit Account" %>

<h1><%= yield :title %></h1>
<%= render :partial => "form" %>
END
# assign default role when creating a user
sentinel = "    @user = User.new(params[:user])\n"
gsub_file_with_match_check "app/controllers/users_controller.rb", /(#{Regexp.escape(sentinel)})/mi, <<-END
#{sentinel}
    @user.role_name = "registered"
END
sentinel = 'post :create, :user => { }'
gsub_file_with_match_check "test/functional/users_controller_test.rb", /(#{Regexp.escape(sentinel)})/mi,
  'post :create, :user => {
        :username => "user1", :email => "user1@example.com",
        :password => "password", :password_confirmation => "password"
    }'
# figure out the migration filename including timestamp
migration = Dir.glob(File.join("db","migrate","*create_users.rb")).first
# add db constraints to the user migration
user_attrs.each do |user_attr|
  if user_attr[:constraints]
    sentinel = ":#{user_attr[:name]}"
    gsub_file_with_match_check migration, /(#{Regexp.escape(sentinel)})/mi do |match|
      format = "%-#{30-user_attr[:type].to_s.length}s"
      format % "#{match}," + user_attr[:constraints].inspect.gsub(/\{:/,'{ :').gsub(/=>/, ' => ').gsub(/\}/, ' }')
    end
  end
end
git :add => ".", :commit => "-m 'add authlogic.'"

gem "refraction"    # redirects
file "config/initializers/refraction_rules.rb", "# Refraction.configure do |req|\n# end"
["development","test","production"].each do |rails_env|
  environment '
# Add middleware.
config.middleware.insert_before(::Rack::Lock, ::Refraction, {})
', :env => rails_env
end
git :add => ".", :commit => "-m 'add refraction.'"

file "config/initializers/connection_fix.rb", <<-END
# If your workers are inactive for a long period of time, they'll lose
# their MySQL connection.
#
# This hack ensures we re-connect whenever a connection is
# lost. Because, really. why not?
#
# Stick this in RAILS_ROOT/config/initializers/connection_fix.rb (or somewhere similar)
#
# From:
#   http://coderrr.wordpress.com/2009/01/08/activerecord-threading-issues-and-resolutions/

module ActiveRecord::ConnectionAdapters
  class MysqlAdapter
    alias_method :execute_without_retry, :execute

    def execute(*args)
      execute_without_retry(*args)
    rescue ActiveRecord::StatementInvalid => e
      if e.message =~ /server has gone away/i
        warn "Server timed out, retrying"
        reconnect!
        retry
      else
        raise e
      end
    end
  end
end
END
git :add => ".", :commit => "-m 'add connection fix.'"

plugin "disable_timestamps_for", :git => "git://github.com/aaronchi/disable_timestamps_for.git" # Selectively disable timestamping on specific fields
git :add => ".", :commit => "-m 'add disable_timestamps_for.'"

plugin "eztime", :svn => "http://svn.webtest.wvu.edu/repos/rails/plugins/eztime/"               # date/time helpers
git :add => ".", :commit => "-m 'add eztime.'"

plugin "query_trace", :git => "git://github.com/ntalbott/query_trace.git"                       # stack dump for SQL statements
sentinel = 'include QueryTrace'
gsub_file_with_match_check "vendor/plugins/query_trace/init.rb", /(#{Regexp.escape(sentinel)})/mi do |match|
  "# Uncomment the next line to turn query_trace on:
  # #{match}"
end
git :add => ".", :commit => "-m 'add query_trace.'"

plugin "hashdown", :git => "git://github.com/rubysolo/hashdown.git"                             # use a table for enum values
git :add => ".", :commit => "-m 'add hashdown.'"

sentinel = 'ENV["RAILS_ENV"] = "test"'
gsub_file_with_match_check "test/test_helper.rb", /(#{Regexp.escape(sentinel)})/mi do |match|
  "#{match}\n" +
  %q{require 'rubygems'
# http://stackoverflow.com/questions/1145318/getting-uninitialized-constant-error-when-trying-to-run-tests
gem 'test-unit'
}
end

sentinel = %q{require 'test_help'}
gsub_file_with_match_check "test/test_helper.rb", /(#{Regexp.escape(sentinel)})/mi do |match|
  "#{match}\nrequire 'shoulda'"
end
gem "mocha", :env => "test"
gem "shoulda", :env => "test"
git :add => ".", :commit => "-m 'add shoulda, mocha, and other requires to test_helper.rb.'"

gsub_file_with_match_check "app/controllers/application_controller.rb", /^end$/,
  %q{
  helper_method :current_user, :logged_in?

private

  # Return the current user session.
  # If refresh is false (the default), we return the same value without looking it up again.
  def current_user_session(refresh=false)
    return @current_user_session if !refresh && defined?(@current_user_session)
    @current_user_session = UserSession.find
  end

  # Return the current user, or an in-memory user with role :guest if no one is logged in.
  # If refresh is false (the default), we return the same value without looking it up again.
  def current_user(refresh=false)
    return @current_user if !refresh && defined?(@current_user)
    @current_user = (current_user_session(refresh) && current_user_session(refresh).record)
    if !@current_user
      @current_user = User.new
      @current_user.role = "guest"
    end
    @current_user
  end

  # is the current user not just a guest?
  def logged_in?
    current_user.may_logout?
  end
end
}
git :add => ".", :commit => "-m 'add current_user_session, current_user, and logged_in? to application_controller.rb.'"

file "app/models/permissions.rb", <<-END
class Permissions < Aegis::Permissions

  role :guest,      :default_permission => :deny
  role :registered, :default_permission => :deny
  role :admin,      :default_permission => :allow

  # ============================= User permissions ==============================

  permission :show_user, :edit_user, :update_user, :destroy_user do |user, other_user|
    allow(:registered) { user.id == other_user.id }
  end
  permission :create_user do
    allow :guest, :registered, :admin
  end
  permission :list_all_users do end
  permission :logout do
    allow :registered
  end

  # ======================== Admin Pages permissions ============================

  permission :view_admin_data, :update_admin_data do end

  # ======================= User Session permissions ============================

  permission :login do
    allow :guest
    deny :registered, :admin
  end
  permission :logout do
    allow :registered, :admin
  end

end
END
git :add => ".", :commit => "-m 'set up default permissions.'"

# user model
sentinel = "class User < ActiveRecord::Base"
gsub_file_with_match_check "app/models/user.rb", /(#{Regexp.escape(sentinel)})/mi do |match|
  <<-END
#{match}
  attr_accessible :username, :email, :password, :password_confirmation
  acts_as_authentic do |c|
    c.merge_validates_format_of_login_field_options( {
      :with => /\\A[A-Za-z][A-Za-z0-9_\\-]*\\z/,
      :message => I18n.t('error_messages.login_invalid') } )
  end
  has_role

  validates_presence_of :role_name

  named_scope :registered, :conditions => "role_name = 'registered'"
  named_scope :admins, :conditions => "role_name = 'admin'"
END
end
git :add => ".", :commit => "-m 'configure user model - attr_accessible, authlogic, and aegis.'"

# home page
generate :controller, "home index"
route %{map.root :controller => "home"}
git :rm => "public/index.html"
git :rm => "public/images/rails.png"
git :rm => "README"
git :add => ".", :commit => "-m 'add home controller and remove readme.'"

# task to assign role to user
file "lib/tasks/user.rake",
  %q{namespace :user do
  desc "Assign a ROLE to USER. Must specify USER=username ROLE=admin or ROLE=registered"
  task :assign_role => [ "environment" ] do
    username = ENV['USER']
    role = ENV['ROLE']
    if !username || !role || !(["admin","registered"].include?(role))
      puts "Must pass USER=username and ROLE=rolename, where rolename is admin or registered"
      exit
    end

    user = User.find_by_username(username)
    if !user
      puts %Q{Can't find user "#{username}"}
      exit
    end

    if user.role.to_s.casecmp(role) == 0
      puts %Q{User "#{username} already had role #{role}"}
      exit
    end

    user.role = role
    user.save!
    puts %Q{Changed role for "#{username}" to #{role}}
  end
end
}
git :add => ".", :commit => "-m 'add rake :assign_role task.'"

sentinel = "# filter_parameter_logging :password"
gsub_file_with_match_check "app/controllers/application_controller.rb", /(#{Regexp.escape(sentinel)})/mi, 'filter_parameter_logging :password, :password_confirmation'
git :add => ".", :commit => "-m 'filter sensitive pararameters in the log.'"

# uncomment the line that specifies SQL instead of schema.rb
sentinel = "config.active_record.schema_format = :sql"
gsub_file_with_match_check "config/environments/test.rb", /# (#{Regexp.escape(sentinel)})/mi, '\1'
git :add => ".", :commit => "-m 'use sql instead of schema dumper when creating the test database, for constraints or db-specific column types.'"

# create some user fixtures
file "test/fixtures/users.yml", <<-END
registered: &base
  username: UserName
  email: user@example.com
  role_name: registered
  # password is "secret"
  crypted_password: "a52c40dab0c1ee2d2d1000ed521baa0ae31f7ef7ad93e8124d00e01ea8b0ee833289502c5a05a8a02ccf179725bf2245fa871976c253b0817023d4bd49884379"
  password_salt: "r_faZ7F2Mn3Xe2XKyjT5 "
  persistence_token: "897e81c9b018b86c3dd4e6cbc5ed2543aea85054854bb48092a3a908b4518b2e62c0ab6ffa5aa2c50d0ec565e3740753b0423d483d2cf1e042050aefd9988ca8"
  single_access_token: "brOVHN60dlqtxTgVOEc3"
  perishable_token: "FuAct39YfiyvWfvtXAYL"
  login_count: 1
  failed_login_count: 0
  last_request_at: 2010-02-05 08:28:00
  current_login_at: 2010-02-05 08:28:00
  last_login_at: 2010-02-05 08:28:00
  current_login_ip: "127.0.0.1"
  last_login_ip: "127.0.0.1"

admin:
  <<: *base
  username: AdminName
  email: admin@example.com
  role_name: admin
END

sentinel = 'users(:one)'
gsub_file_with_match_check "test/functional/users_controller_test.rb", /(#{Regexp.escape(sentinel)})/mi, 'users(:registered)'
git :add => ".", :commit => "-m 'add fixtures.'"

# add application helpers
gsub_file_with_match_check "app/helpers/application_helper.rb", /^end$/,
  %q{

  def title(page_title, show_title = true)
    @content_for_title = page_title.to_s
    @show_title = show_title
  end

  def show_title?
    @show_title
  end

  def body_id(page_body_id)
    @content_for_body_id = "id='#{h(page_body_id)}'"
  end
end
}
git :add => ".", :commit => "-m 'add application helpers.'"

# Create YUI CSS include file
file "app/views/layouts/_yui_css.html.erb", <<-END
<%# from http://developer.yahoo.com/yui/articles/hosting/?base#configure %>
<%# options selected: Combine Files, Allow Rollup, Reset , Base, Fonts %>
<% if RAILS_ENV == "development" %>
  <!-- Combo-handled YUI CSS files: -->
  <link rel="stylesheet" type="text/css" href="http://yui.yahooapis.com/combo?2.7.0/build/fonts/fonts-min.css&amp;2.7.0/build/reset/reset-min.css&amp;2.7.0/build/base/base-min.css&amp;2.7.0/build/logger/assets/skins/sam/logger.css" />
<% else %>
  <!-- Combo-handled YUI CSS files: -->
  <link rel="stylesheet" type="text/css" href="http://yui.yahooapis.com/combo?2.7.0/build/reset-fonts/reset-fonts.css&amp;2.7.0/build/base/base-min.css" />
<% end %>
END
git :add => ".", :commit => "-m 'add YUI.'"

# copy jQuery
run "curl http://code.jquery.com/jquery-#{jquery_ver}.min.js > public/javascripts/jquery-#{jquery_ver}.min.js"
run "curl http://code.jquery.com/jquery-#{jquery_ver}.js     > public/javascripts/jquery-#{jquery_ver}.js"

# include normal or minified jquery
file "app/views/layouts/_jquery.html.erb", <<-END
<% if RAILS_ENV == "development" %>
  <%= javascript_include_tag "jquery-#{jquery_ver}", :cache => "jquery" %>
<% else %>
  <%= javascript_include_tag "jquery-#{jquery_ver}.min", :cache => "jquery" %>
<% end %>
}
END
git :add => ".", :commit => "-m 'add jQuery.'"

# add application.css
file "public/stylesheets/application.css", <<-END
body                             { color: #333; }
body, p, ol, ul, td              { font-family: verdana, arial, helvetica, sans-serif; }
th, td                           { border: none; }
a                                { color: #000; }
a:visited                        { color: #666; }
END
git :add => ".", :commit => "-m 'add application.css.'"

# Make the default layout
file "app/views/layouts/application.html.erb", <<-END
<!DOCTYPE html>
<html>
  <head>
    <title><%= h(yield(:title)) %></title>
    <%= render :partial => "/layouts/yui_css" %>
    <%= stylesheet_link_tag "application", :cache => "all" %>
    <!--[if IE 7]>
    <%= stylesheet_link_tag "ie7" %>
    <![endif]-->
    <% min = RAILS_ENV == "development" ? "" : ".min" %>
    <%= javascript_include_tag "jquery-#{jquery_ver}\#{min}", :cache => "all" %>
    <%= yield(:head) %>
  </head>
  <body <%= yield(:body_id) %> >
    <%= yield %>
  </body>
</html>
END
git :add => ".", :commit => "-m 'create application layout.'"

# remove Prototype
[ "controls", "dragdrop", "effects", "prototype" ].each do |filename|
  git :rm => "public/javascripts/#{filename}.js"
end
git :add => ".", :commit => "-m 'remove Prototype.'"

# force all models to use attr_accessible - http://guides.rubyonrails.org/security.html
file "config/initializers/force_attr_accessible.rb", "ActiveRecord::Base.send(:attr_accessible, nil)"
git :add => ".", :commit => "-m 'force all models to use attr_accessible'"

# Have to add admin_data plugin near the end of this script.
# Adding it too soon results in a Mysql error when generating a conroller.
plugin "admin_data", :git => "git://github.com/neerajdotname/admin_data.git"                    # admin pages
file "config/initializers/admin_data_settings.rb", '
AdminDataConfig.set = {
  :is_allowed_to_view => lambda {|controller| return true if current_user.may_view_admin_data? },
  :is_allowed_to_update => lambda {|controller| return true if current_user.may_update_admin_data? },
}
'
git :add => ".", :commit => "-m 'add admin_data.'"

# TODO:
# - convert from template to builder? See http://pivotallabs.com/users/mbarinek/blog/articles/1437-rails-3-application-builders
#   - Would lose incremental git adds and commits.
#   - Code might be cleaner.
#   - Make a class that extends Rails::AppBuilder (railties/lib/rails/generators/rails/app/app_generator).
#     - Override methods in Rails::AppBuilder to modify the built-in behavior.
#     - Add new methods that will be called at the end.
# - add jquery-ui?
# - add my stuff for updating the flash with ajax
# - support the "current" ID for user actions.  Then uncomment the edit-account route.
# - copy the permission checks and similar logic from users_controller.rb in upatwee
# - redirect someplace better than /users/1/show after creating a user account
# - fix users/show.html.erb to show something reasonable (don't divulge ip, last login, etc.)
# - add airbrake or exceptional
# - add new relic
# - add https://github.com/37signals/fast_remote_cache
# - see https://github.com/ffmike/BigOldRailsTemplate for more ideas
# - add https://github.com/eliotsykes/asset_fingerprint
# - add https://transfs.com/devblog/2010/05/05/tame-your-analytics-libraries-with-analytical/
# - add https://github.com/jbr/freighthopper
# - add https://github.com/qmx/canivete for the 'deprecate' method
# - add https://github.com/paneq/activemodel-warnings ?
# - add https://github.com/josevalim/rails-footnotes ?
# - write a brian_scaffold that:
#   - uses aegis permissions
#   - generates tests for aegis permissions
#   - generates "current_user" and "current_user=" methods in test_helper?
#   - uses helper methods instead of @instance variables
#   - returns both xml and json
#   - makes a _form partial like nifty_generator
#   - uses will_paginate in the controller and the view
#   - creates an attr_accessible statement in the model, like nifty_generator
#   - requires shoulda in test_helper.rb
# - add attr_encodable for JSON APIs
