append_file "config/deploy.rb", %q{

# Build native gems
task :build_gems do
  run "cd #{release_path}; RAILS_ENV=#{fetch :rails_env} rake gems:build"
end
after "deploy:update_code", :build_gems
}
git :add => ".", :commit => "-m 'build native gems when deploying.'"
