require 'rubygems'
require 'sinatra'
require 'json'
require 'warden'
require 'data_mapper'
require 'openssl'
require 'sinatra/static_assets'
require 'date'
require 'linguistics'
require 'sanitize'
require 'fileutils'
#require 'FileUtils'
require 'resolv'
require 'aws/s3'

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

  property :id,               Serial
  property :password,         String, :required => true
  property :created_at,       DateTime
  property :firstname,        String
  property :lastname,         String
  property :email,            String, :unique => true, :required => true
  property :email_shared,     String
  property :phone,            String
  property :phone_shared,     String

  # Public class method than returns a user object if the caller supplies the correct name and password
  #
  def self.authenticate(email, password)
    user = first(:email => email)
    if user
      if user.password != OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha1'), "secretsalt", password)
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

  class Image
    include DataMapper::Resource
    property :id,         Serial
    property :created_at, DateTime
    property :filename,   String, :required => true
    property :url,        String, :required => true      
  end

DataMapper.finalize


#User.create(:username => 'user', :password => OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('md5'), "secretsalt", 'qwerty'))
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
    
    params['email'] || params['password']
  end
  
  def authenticate!
    puts '[INFO] password strategy authenticate'

    u = User.authenticate(params['email'], params['password'])
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
      @users = User.all(:order => :lastname)
      @messages = Message.all(:recipient => env['warden'].user.id) + Message.all(:sender => env['warden'].user.id)
      erb :index
end

# create new task   
post '/book/create' do
  book = Book.new(:name => Sanitize.clean(params[:name]), :author => Sanitize.clean(params[:author]), :price => params[:price], :description => Sanitize.clean(params[:description]), :owner => env['warden'].user.id, :created_at => Time.now)
  if book.save
    status 201
    redirect '/'  
  else
    status 412
    redirect '/'   
  end
end

post '/book/new' do
  book = Book.new(:name => Sanitize.clean(params[:name]), :author => Sanitize.clean(params[:author]), :price => params[:price] ? params[:price] : 0, :description => Sanitize.clean(params[:description]), :owner => env['warden'].user.id, :created_at => Time.now)
  if book.save
    status 201
  else
    status 412 
  end
end

# create new message   
post '/message/create' do
  puts User.get(params[:sender]).firstname+" "+User.get(params[:sender]).lastname+" sends a message saying "+params[:body]+" to "+User.first(:id => params[:recipient]).firstname+" "+User.first(:id => params[:recipient]).lastname
  # puts JSON.parse(request.body.read.to_s)
  message = Message.new(:body => Sanitize.clean(params[:body]), :sender => params[:sender], :read => false, :sent_at => Time.now, :recipient => params[:recipient])
  if message.save
    status 201
  else
    status 412
  end
end

post '/user/create' do
  if validate_email_spelling(params[:email]) and validate_email_domain(params[:email])
    user = User.create(:firstname => Sanitize.clean(params[:firstname]), :lastname => Sanitize.clean(params[:lastname]), :created_at => Time.now, :phone => Sanitize.clean(params[:phone]), :email=>Sanitize.clean(params[:email]), :email_shared => "yes", :phone_shared => "yes", :password => OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha1'), "secretsalt", params[:password]))
    if user.save
      status 201
      env['warden'].authenticate!
      redirect '/'
    else
      status 412
      redirect '/login'
    end
  else
    redirect '/login'
  end
end

 # edit task
get '/book/:id' do
  if !env['warden'].user
    session[:crumb_path] = env['PATH_INFO']
    redirect '/login' 
  elsif Book.get(params[:id])
    @users = User.all(:order => :lastname)
    @book = Book.get(params[:id])
    @title = Book.get(params[:id]).name+" - Book Exchange"
    erb :edit
  else
    redirect '/'
  end
end

 # edit task
get '/inbox_listings' do
  if !env['warden'].user
  else
    user = env['warden'].user
    @messages = Message.all(:conditions =>["sender = ? OR recipient = ?", user.id, 
user.id], :order => :sent_at)
    erb :inbox_listings, :layout=> false
  end
end

get '/inbox' do
  if !env['warden'].user
    session[:crumb_path] = env['PATH_INFO']
    redirect '/login'
  else
    user = env['warden'].user
    @users = User.all(:order => :lastname)
    @messages = Message.all(:conditions =>["sender = ? OR recipient = ?", user.id, 
user.id], :order => :sent_at)
    erb :inbox
  end
end

get '/user/:id' do
  if !env['warden'].user
    session[:crumb_path] = env['PATH_INFO']
    redirect '/login' 
  elsif User.get(params[:id])
    @users = User.all(:order => :lastname)
    @user = User.get(params[:id])
    @title = User.get(params[:id]).firstname+" "+User.get(params[:id]).lastname+"'s profile - Book Exchange"
    @books = Book.all(:owner => params[:id], :order=> :created_at)
    erb :profile
  else
    redirect '/'
  end
end

post '/user' do
  if !env['warden'].user
  elsif User.get(params[:id]) and !params[:delete]
    @user  = User.get(params[:id])
    @title = User.get(params[:id]).firstname+" "+User.get(params[:id]).lastname+"'s profile - Book Exchange"
    @books = Book.all(:owner => params[:id], :order=> [:created_at.desc])
    erb :profile, :layout => false
  elsif User.get(params[:id]) and params[:delete]
    @user = User.get(params[:id])
    @ajax = true
    erb :delete_account, :layout => false
  end
end

post '/user/update' do
  if env['warden'].user
    if validate_email_spelling(params[:email]) and validate_email_domain(params[:email])
      if User.get(params[:id]) and !params[:password]
        if User.get(params[:id])==env['warden'].user
          user              = User.get(params[:id])
          user.firstname    = Sanitize.clean(params[:firstname])
          user.lastname     = Sanitize.clean(params[:lastname])
          user.phone        = Sanitize.clean(params[:phone])
          user.email        = Sanitize.clean(params[:email])
          user.email_shared = params[:email_shared]
          user.phone_shared = params[:phone_shared]
            if user.save
              status 201
              redirect '/'
            else
              status 412
              redirect '/'
            end
        end
      elsif User.get(params[:id]) and params[:password] and !params[:newpassword]
        if User.get(params[:id])==env['warden'].user
          user              = User.get(params[:id])
          user.firstname    = Sanitize.clean(params[:firstname])
          user.lastname     = Sanitize.clean(params[:lastname])
          user.phone        = Sanitize.clean(params[:phone])
          user.email        = Sanitize.clean(params[:email])
          user.email_shared = params[:email_shared]
          user.phone_shared = params[:phone_shared]
            if user.save
              status 201
              redirect '/'
            else
              status 412
              redirect '/'
            end
        end
      elsif User.get(params[:id]) and params[:password]==params[:newpassword]
        if User.get(params[:id])==env['warden'].user
          user              = User.get(params[:id])
          user.firstname    = Sanitize.clean(params[:firstname])
          user.lastname     = Sanitize.clean(params[:lastname])
          user.phone        = Sanitize.clean(params[:phone])
          user.email        = Sanitize.clean(params[:email])
          user.email_shared = params[:email_shared]
          user.phone_shared = params[:phone_shared]
            if user.save
              status 201
              redirect '/'
            else
              status 412
              redirect '/'
            end
        end
      elsif User.get(params[:id]) and params[:password]!=params[:newpassword] and params[:newpassword]!=""
        if User.get(params[:id])==env['warden'].user and User.get(params[:id]).password == OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha1'), "secretsalt", params[:password])
          user              = User.get(params[:id])
          user.firstname    = Sanitize.clean(params[:firstname])
          user.lastname     = Sanitize.clean(params[:lastname])
          user.phone        = Sanitize.clean(params[:phone])
          user.email        = Sanitize.clean(params[:email])
          user.email_shared = params[:email_shared]
          user.phone_shared = params[:phone_shared]
          user.password     = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha1'), "secretsalt", params[:newpassword])
          if user.save
            status 201
            redirect '/'
          else
            status 412
            redirect '/'
          end
        end
      else
        redirect '/'
      end
    else
      redirect '/'
    end
  end
end


get '/listings' do
  @books = Book.all(:order => :author)
  erb :book_listings, :layout => false
end

post '/book' do
  if !env['warden'].user
  elsif Book.get(params[:id]) and !params[:delete]
    @book  = Book.get(params[:id])
    @title = Book.get(params[:id]).name+" - Book Exchange"
    erb :edit_fancy, :layout => false
  elsif Book.get(params[:id]) and params[:delete]
    @book = Book.get(params[:id])
    @ajax = true
    erb :delete, :layout => false
  end
end

# get '/user/search' do
#   if env['warden'].user
#     puts params[:term]
#     @response = User.all(:username => params[:term])
#     # puts @response
#     # @responsejson = []
#     @response.each do |match|
#       puts match.username+" found"
#     end
#     @response.to_json
#   end
# end

# update task
put '/book/:id' do
  book             = Book.get(params[:id])
  book.sold_at     = params[:sold] ?  Time.now : nil
  book.description = Sanitize.clean(params[:description])
  book.name        = Sanitize.clean(params[:name])
  book.author      = Sanitize.clean(params[:author])
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

post '/book/update' do
  puts params[:sold] ? "true" : "false"
  book             = Book.get(params[:id])
  book.sold_at     = params[:sold] ?  Time.now : nil
  book.description = Sanitize.clean(params[:description])
  book.name        = Sanitize.clean(params[:name])
  book.author      = Sanitize.clean(params[:author])
  book.price       = params[:price]
  book.sold        = params[:sold]
  if book.save
    status 201
  else
    status 412
  end
end

# delete confirmation
get '/book/:id/delete' do
  redirect '/login' unless env['warden'].user
  @users = User.all(:order => :lastname)
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

delete '/user/:id' do
  redirect '/login' unless env['warden'].user
  Book.all(:owner=>params[:id]).each do |book|
    book.destroy
  end
  Message.all(:sender=>params[:id]).each do |m|
    m.destroy
  end
  User.get(params[:id]).destroy
  env['warden'].logout
  redirect '/'  
end

# post '/upload' do
#   puts params[:image]
#   puts params[:image][:tempfile].path
#   n = Image.new
#   n.filename = params[:image][:filename]
#   n.created_at = Time.now
#   FileUtils.copy(params[:image][:tempfile].path, "./public/uploads/"+params[:image][:filename])
#   n.url = "/uploads/#{params[:image][:filename]}"
#   if n.save 
#     redirect '/'
#   else
#     redirect '/'
#   end
# end

post '/upload' do
  unless params[:image] && (tmpfile = params[:image][:tempfile]) && (name = params[:image][:filename])
    redirect '/'
  end
  while blk = tmpfile.read(65536)
    AWS::S3::Base.establish_connection!(
    :access_key_id     => ENV[':s3_key'],
    :secret_access_key => ENV[':s3_secret'])
    AWS::S3::S3Object.store(name,open(tmpfile),ENV[':bucket'],:access => :public_read)     
  end
  n = Image.new
  n.created_at = Time.now
  n.filename = params[:image][:filename]
  n.url = "http://#{ENV[':bucket']}.s3.amazonaws.com/#{params[:image][:filename]}"
  if n.save 
    redirect '/gallery'
  else
    "failure"
  end
end

get '/gallery' do
  @pictures = Image.all(:order => :created_at)
  erb :gallery, :layout => false
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

def validate_email_domain(email)
      if (email.match(/\@(.+)/)[1])
        domain = email.match(/\@(.+)/)[1]
        Resolv::DNS.open do |dns|
            @mx = dns.getresources(domain, Resolv::DNS::Resource::IN::MX)
        end
        @mx.size > 0 ? true : false
      else
        false
      end
end

def validate_email_spelling(email)
  email =~ /^[a-zA-Z][\w\.-]*[a-zA-Z0-9]@[a-zA-Z0-9][\w\.-]*[a-zA-Z0-9]\.[a-zA-Z][a-zA-Z\.]*[a-zA-Z]$/ ? true : false
end








