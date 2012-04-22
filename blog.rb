
require 'rubygems'
require 'sinatra'
require 'json'
require 'warden'
require 'data_mapper'
require 'openssl'
require 'sinatra/static_assets'
require 'date'
require 'linguistics'
Linguistics::use( :en )

DataMapper.setup(:default, ENV['DATABASE_URL'] || "sqlite3://#{Dir.pwd}/development.db")

class Book
  include DataMapper::Resource
  property :id,               Serial
  property :author,           String, :required => true
  property :name,             String, :required => true
  property :sold_at,          DateTime
  property :created_at,       DateTime
  property :price,            Float
  property :sold,             String
  property :description,      Text
  property :owner,            Integer
end

class Message
  include DataMapper::Resource
  property :id,               Serial
  property :recipient,        Integer, :required => true
  property :read,             Boolean
  property :sent_at,          DateTime
  property :body,             Text
  property :sender,           Integer
end

class User
  include DataMapper::Resource

  property :id,       Serial
  property :username, String, :unique => true
  property :password, String

  # Public class method than returns a user object if the caller supplies the correct name and password
  #
  def self.authenticate(username, password)
    user = first(:username => username)
    if user
      if user.password != OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('md5'), "secretsalt", password)
        user = nil
      end
    end
    user
  end

  # def self.authenticate(username, password)
  #       #TODO: Store salt in config
  #       user = self.first(:username => username) 
  #       user if user && (user.password == OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('md5'), "secretsalt", password))
  # end

  # def self.signup(username, password)
  #       AppUser.create(
  #           :username => username, 
  #           :password => OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('md5'), "secretsalt", password),
  #           :created_at => Time.now
  #       )
  # end


end

DataMapper.finalize


User.create(:username => 'user', :password => OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('md5'), "secretsalt", 'qwerty'))
use Rack::Session::Cookie, :secret => "bla-bla-bla"

use Warden::Manager do |manager|
  manager.default_strategies :password
  manager.failure_app = FailureApp.new
end

### Session Setup
# Tell Warden how to serialize the user in and out of the session.
#
Warden::Manager.serialize_into_session do |user|
  puts '[INFO] serialize into session'
  user.id
end

Warden::Manager.serialize_from_session do |id|
  puts '[INFO] serialize from session'
  User.get(id)
end
###

Warden::Strategies.add(:password) do
  def valid?
    puts '[INFO] password strategy valid?'
    
    params['username'] || params['password']
  end
  
  def authenticate!
    puts '[INFO] password strategy authenticate'

    u = User.authenticate(params['username'], params['password'])
    u.nil? ? fail!('Could not login in') : success!(u)
  end
end
###

class FailureApp
  def call(env)
    uri = env['REQUEST_URI']
    puts "failure #{env['REQUEST_METHOD']} #{uri}"
  end
end

get '/login/?' do
  if env['warden'].authenticate
    redirect '/'
  else
    @title = "Login/Sign-up - Book Exchange"
    erb :login
  end
end

post '/login/?' do
  if env['warden'].authenticate
    redirect session[:crumb_path] || '/'
  else
    session[:crumb_path] = env['PATH_INFO']
    puts "storing crumb path"+env['PATH_INFO']
    redirect '/login'
  end
end

get '/logout/?' do
  env['warden'].logout
  redirect '/'
end


# list all tasks
get '/' do
      redirect '/login' unless env['warden'].user
      @books = Book.all(:order => :author)
      @users = User.all(:order => :username)
      @messages = Message.all(:recipient => env['warden'].user.id) + Message.all(:sender => env['warden'].user.id)
      erb :index
end

# create new task   
post '/book/create' do
  book = Book.new(:name => params[:name], :author => params[:author], :price => params[:price] ? params[:price] : 0, :description => params[:description], :owner => env['warden'].user.id, :created_at => Time.now)
  if book.save
    status 201
    redirect '/'  
  else
    status 412
    redirect '/'   
  end
end

# create new message   
post '/message/create' do
  puts User.get(params[:sender]).username+" sends a message saying "+params[:body]+" to "+User.first(:username => params[:recipient]).username
  # puts JSON.parse(request.body.read.to_s)
  message = Message.new(:body => params[:body], :sender => params[:sender], :read => false, :sent_at => Time.now, :recipient => User.first(:username => params[:recipient]).id)
  if message.save
    status 201
  else
    status 412
  end
end

post '/user/create' do
  user = User.create(:username => params[:username], :password => OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('md5'), "secretsalt", params[:password]))
  if user.save
    status 201
    env['warden'].authenticate!
    redirect '/'
  else
    status 412
    redirect '/login'
  end
end

 # edit task
get '/book/:id' do
  if !env['warden'].user
    session[:crumb_path] = env['PATH_INFO']
    redirect '/login' 
  elsif Book.get(params[:id])
    @book = Book.get(params[:id])
    @title = Book.get(params[:id]).name+" - Book Exchange"
    erb :edit
  else
    redirect '/'
  end
end

get '/user/search' do
  if env['warden'].user
    puts params[:term]
    @response = User.all(:username.like => params[:term])
    # puts @response
    # @responsejson = []
    @response.each do |match|
      puts match.username+" found"
    end
    @response.to_json
  end
end

# update task
put '/book/:id' do
  book             = Book.get(params[:id])
  book.sold_at     = params[:sold] ?  Time.now : nil
  book.description = params[:description]
  book.name        = params[:name]
  book.author      = params[:author]
  book.price       = params[:price]
  book.sold        = params[:sold]
  if book.save
    status 201
    redirect '/'
  else
    status 412
    redirect '/'   
  end
end

# delete confirmation
get '/book/:id/delete' do
  redirect '/login' unless env['warden'].user
  @book = Book.get(params[:id])
  @title = "Remove "+Book.get(params[:id]).name+" - Book Exchange"
  erb :delete
end

# delete task
delete '/book/:id' do
  redirect '/login' unless env['warden'].user
  Book.get(params[:id]).destroy
  redirect '/'  
end

DataMapper.auto_upgrade!

def pluralize(number, text)
  return text.en.plural if number != 1
  text
end

def relative_time(start_time)
  diff_seconds = Time.now.to_i - start_time.to_i
  case diff_seconds
    when 0 .. 59
       "just now"
    when 60 .. (3600-1)
       "#{diff_seconds/60} "+pluralize((diff_seconds/60), 'minute')+" ago"
    when 3600 .. (3600*24-1)
       "#{diff_seconds/3600} "+pluralize((diff_seconds/3600), 'hour')+" ago"
    when (3600*24) .. (3600*24*7-1) 
       "#{diff_seconds/(3600*24)} "+pluralize((diff_seconds/(3600*24)), 'day')+" ago"
    when (3600*24*7) .. (3600*24*30)
       "#{diff_seconds/(3600*24*7)} "+pluralize((diff_seconds/(3600*24*7)), 'week')+" ago"
    else
       start_time.strftime("%m/%d/%Y")
  end
end