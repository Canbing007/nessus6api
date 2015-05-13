#!/usr/bin/env ruby

### Nessus v6 API methods

require 'net/https'
require 'json'
require 'uri'
require 'getoptlong'

module NessusClient
  class Nessus6API
    class << self
      @connection
      @token
    end
     
    def initialize(host, username = nil, password = nil, ssl_option = nil)
      uri = URI.parse(host)
      @connection = Net::HTTP.new(uri.host, uri.port)
      @connection.use_ssl = true
      if ssl_option == "ssl_verify"
        @connection.verify_mode = OpenSSL::SSL::VERIFY_PEER
      else
        @connection.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
        
      yield @connection if block_given?
        authenticate(username, password) if username && password
    end
 
    def authenticate(username, password)
      payload = {
        :username => username, 
        :password => password, 
        :json => 1
      }
      res = http_post(:uri=>"/session", :data=>payload)
      if res['token']
        @token = "token=#{res['token']}"
        return true
      else
        false
      end
    end

    def x_cookie
      {'X-Cookie'=>@token}
    end

    alias_method :login, :authenticate
     
    def authenticated
    puts "\nauthenticated called"
      if (@token && @token.include?('token='))
        return true
      else
        return false
      end
    end

    def get_server_properties
      http_get(:uri=>"/server/properties", :fields=>x_cookie)
    end
  
    def user_add(username, password, permissions, type)
      payload = {
        :username => username, 
        :password => password, 
        :permissions => permissions, 
        :type => type, 
        :json => 1
      }
      http_post(:uri=>"/users", :fields=>x_cookie, :data=>payload)
    end
      
    def user_delete(user_id)
      res = http_delete(:uri=>"/users/#{user_id}", :fields=>x_cookie)
      return res.code
    end
      
    def user_chpasswd(user_id, password)
      payload = {
        :password => password, 
        :json => 1
      }
      res = http_put(:uri=>"/users/#{user_id}/chpasswd", :data=>payload, :fields=>x_cookie)
      return res.code
    end
      
    def user_logout
      res = http_delete(:uri=>"/session", :fields=>x_cookie)
      return res.code
    end

    def policy_get_id(textname)
      resp = http_get(:uri=>"/policies", :fields=>x_cookie)
      resp['policies'].each { |list|
		if list['name'] == textname
		  puts "\nPolicy #{list['name']} (Policy ID: #{list['id']}) will be used for this scan."
		  return list['id']
		end
	  }
		return ''
    end
        
    def list_policies
      http_get(:uri=>"/policies", :fields=>x_cookie)
    end

    def list_users
      http_get(:uri=>"/users", :fields=>x_cookie)
    end

    def list_folders
      http_get(:uri=>"/folders", :fields=>x_cookie)
    end

    def list_scanners
      http_get(:uri=>"/scanners", :fields=>x_cookie)
    end

    def list_families
      http_get(:uri=>"/plugins/families", :fields=>x_cookie)
    end

    def list_plugins(family_id)
      http_get(:uri=>"/plugins/families/#{family_id}", :fields=>x_cookie)
    end

    def list_template(type)
      res = http_get(:uri=>"/editor/#{type}/templates", :fields=>x_cookie)
    end

    def plugin_details(plugin_id)
      http_get(:uri=>"/plugins/plugin/#{plugin_id}", :fields=>x_cookie)
    end

    def is_admin
      res = http_get(:uri=>"/session", :fields=>x_cookie)
      if res['permissions'] == 128
        return true
      else
        return false
      end
    end

    def server_properties
      http_get(:uri=>"/server/properties", :fields=>x_cookie)
    end

#    def scan_create(uuid, name, description, targets)
     def scan_create(uuid, pid, name, targets)
      payload = {
        :uuid => uuid, 
        :settings => {
          :policy_id => pid, 
          :name => name,
          #:description => description, 
          :use_dashboard => "true",
          :text_targets => targets,
          },
        :json => 1
      }.to_json
      http_post(:uri=>"/scans", :body=>payload, :fields=>x_cookie, :ctype=>'application/json')
    end


### New define
    def scan_configure(scanname)
      list=http_get(:uri=>"/scans/", :fields=>x_cookie)
      list['scans'].each { |scan|
		if scan['name'] == scanname
		  $scanid=scan['id']
		  #details=http_get(:uri=>"/scans/#{scanid}", :fields=>x_cookie)
		  return details
		  $name=scanname
		  $policyname=scan['policy']
		  scan['target']
		  newscan=scan
		  scan_configure.keys.each do |key|
		    if key == 'target'
		      newscan[key]=newvalue
		    else
		      newscan[key]=scan[key]
		    end
		  end
		  
		  		  $policyid=self.policy_get_id($policyname)
		end
	  }
		return 'Scan not found!'
    
    
	  payload = {
        :uuid => uuid, 
        :settings => {
          :policy_id => pid, 
          :name => name,
          #:description => description, 
          :use_dashboard => "true",
          :text_targets => targets,
          },
        :json => 1
      }.to_json
	  resp = http_put(:uri=>"/scans/#{scan_id}", :body=>payload, :fields=>x_cookie, :ctype=>'application/json')
	  puts resp
    end    
    
###     
    def scan_launch(scan_id)
      payload = {
	  	  :ContentLength => '0',
		  :json => 1
	  }.to_json
	  resp = http_post(:uri=>"/scans/#{scan_id}/launch", :body=>payload, :fields=>x_cookie, :ctype=>'application/json')
	  puts resp
    end

    def server_status
      http_get(:uri=>"/server/status", :fields=>x_cookie)
    end

    def scan_status(scanname)
      status=http_get(:uri=>"/scans/", :fields=>x_cookie)
      status['scans'].each { |scan|
		if scan['name'] == scanname
		  puts "\nScan Name: #{scan['name']}\tScan ID: #{scan['id']}"
		  return scan['status']
		end
	  }
		return 'Scan not found!'
    end

    def scan_list
      http_get(:uri=>"/scans", :fields=>x_cookie)
    end

    def scan_details(scanname)
      list=http_get(:uri=>"/scans/", :fields=>x_cookie)
      list['scans'].each { |scan|
		if scan['name'] == scanname
		  scanid=scan['id']
		  details=http_get(:uri=>"/scans/#{scanid}", :fields=>x_cookie)
		  return details
		end
	  }
		return 'Scan not found!'
    end

    def scan_pause(scan_id)
      http_post(:uri=>"/scans/#{scan_id}/pause", :fields=>x_cookie)
    end

    def scan_resume(scan_id)
      http_post(:uri=>"/scans/#{scan_id}/resume", :fields=>x_cookie)
    end

    def scan_stop(scan_id)
      http_post(:uri=>"/scans/#{scan_id}/stop", :fields=>x_cookie)
    end

    def scan_export(scan_id, format)
      payload = {
        :format => format
      }.to_json
      http_post(:uri=>"/scans/#{scan_id}/export", :body=>payload, :ctype=>'application/json', :fields=>x_cookie)
    end

    def scan_export_status(scan_id, file_id)
      request = Net::HTTP::Get.new("/scans/#{scan_id}/export/#{file_id}/status")
      request.add_field("X-Cookie", @token)
      res = @connection.request(request)
      if res.code == "200"
        return "ready"
      else
        res = JSON.parse(res.body)
        return res
      end
    end

    def policy_delete(policy_id)
      res = http_delete(:uri=>"/policies/#{policy_id}", :fields=>x_cookie)
      return res.code
    end

    def host_detail(scan_id, host_id)
      res = http_get(:uri=>"/scans/#{scan_id}/hosts/#{host_id}", :fields=>x_cookie)
    end

    def report_download(scan_id, file_id)
      res = http_get(:uri=>"/scans/#{scan_id}/export/#{file_id}/download", :raw_content=> true, :fields=>x_cookie)
    end

    private

    def http_put(opts={})
      uri    = opts[:uri]
      data   = opts[:data]
      fields = opts[:fields] || {}
      res    = nil

      req = Net::HTTP::Put.new(uri)
     
      req.set_form_data(data) unless data.nil?
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        res = @connection.request(req)
      rescue URI::InvalidURIError
        return res
      end

      res
    end

    def http_delete(opts={})
      uri    = opts[:uri]
      fields = opts[:fields] || {}
      res    = nil

      req = Net::HTTP::Delete.new(uri)

      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        res = @connection.request(req)
      rescue URI::InvalidURIError
        return res
      end

      res
    end

    def http_get(opts={})
      uri    = opts[:uri]
      fields = opts[:fields] || {}
      raw_content = opts[:raw_content] || false
      json   = {}

      req = Net::HTTP::Get.new(uri)
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        res = @connection.request(req)
      rescue URI::InvalidURIError
        return json
      end
      if !raw_content
        parse_json(res.body)
      else
        res.body
      end
    end

    def http_post(opts={})
      uri    = opts[:uri]
      data   = opts[:data]
      fields = opts[:fields] || {}
      body   = opts[:body]
      ctype  = opts[:ctype]
      json   = {}

      req = Net::HTTP::Post.new(uri)
      req.set_form_data(data) unless data.nil?
      req.body = body unless body.nil?
      req['Content-Type'] = ctype unless ctype.nil?
      fields.each_pair do |name, value|
        req.add_field(name, value)
      end

      begin
        res = @connection.request(req)
      rescue URI::InvalidURIError
        return json
      end

      parse_json(res.body)
    end

    def parse_json(body)
      buf = {}

      begin
        buf = JSON.parse(body)
      rescue JSON::ParserError
      end

      buf
    end

  end
end

### Nessus v6 API Calls
### Main program

verbose = 0
debug = 0
operation = ''
targets = ''
deletereport = false
user = ''
password = ''
scanname = ''
output = ''
output1 = ''
wait = ''
pid = ''
url = ''
uuid = 'ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66'
policy = ''


def intro 
  $stderr.print $0 + ": Nessus command line interface\n"
  $stderr.print "\n"
end

#intro

def give_help
  puts <<-EOF
Usage:
--user|-u <user>	user for login to Nessus server
--password|-p <pass>	password for login to Nessus server
--scan|-s <name>	start scan with name
--target|-t <ip>	specify list of targets, separated by comma
--policy|-P <policy>	specify policy to use (name of policy)
--url|-U <url>		url of Nessus server
--wait|-w [t]		wait scan to finish (ask in regular periods of <t> for status)
--output|-o <f>		output report XML to file <f>
--output1|-1 <f>	output report XML v1 to file <f>
--reportdelete|-D <id> 	delete report after finish or delete report by id (if alone)
--stop|-S <id>		stop scan identified by <id>
--stop-all|-A		stop all scans
--pause|-q <id>		pause scan identified by <id>
--pause-all|-Q 		pause all scans
--resume|-e <id>	resume scan identified by <id>
--resume-all|-E		resume all scans
--report|-r <id>	download report identified by <id>
--list-scans|-l		list scans
--list-policy|-L	list policies
--status|-W <name>	get status of scan by <name>
--details|-i <name>	get details of scan by <name>
--add-targets|-a <name> configure scan with list of additional targets.  
--verbose|-v		be verbose
--debug|-d		be even more verbose
--help|-h		this help
Examples: 
#{$0} --user xyz --password abc --url https://10.10.10.10 --list-scan
#{$0} -u xyz -p abc -U https://10.10.10.10 -s testscan1 -t localhost -P policy1
EOF
  exit 0
end

if ARGV.length < 1
  give_help
end

opt = GetoptLong.new(
  ["--help", "-h", GetoptLong::NO_ARGUMENT],
  ["--verbose", "-v", GetoptLong::OPTIONAL_ARGUMENT],
  ["--debug", "-d", GetoptLong::OPTIONAL_ARGUMENT],
  ["--target", "-t", GetoptLong::REQUIRED_ARGUMENT],
  ["--user", "-u", GetoptLong::REQUIRED_ARGUMENT],
  ["--password", "-p", GetoptLong::REQUIRED_ARGUMENT],
  ["--policy", "-P", GetoptLong::OPTIONAL_ARGUMENT],
  ["--url", "-U", GetoptLong::REQUIRED_ARGUMENT],
  ["--deletereport", "-D", GetoptLong::OPTIONAL_ARGUMENT],
  ["--wait", "-w", GetoptLong::OPTIONAL_ARGUMENT],
  ["--scan", "-s", GetoptLong::REQUIRED_ARGUMENT],
  ["--list-scans", "-l", GetoptLong::NO_ARGUMENT],
  ["--list-policy", "-L", GetoptLong::NO_ARGUMENT],
  ["--status", "-W", GetoptLong::REQUIRED_ARGUMENT],
  ["--add-targets", "-a", GetoptLong::OPTIONAL_ARGUMENT],
  ["--details", "-i", GetoptLong::REQUIRED_ARGUMENT],
  ["--stop", "-S", GetoptLong::REQUIRED_ARGUMENT],
  ["--stop-all", "-A", GetoptLong::NO_ARGUMENT],
  ["--pause", "-q", GetoptLong::REQUIRED_ARGUMENT],
  ["--pause-all", "-Q", GetoptLong::NO_ARGUMENT],
  ["--resume", "-e", GetoptLong::REQUIRED_ARGUMENT],
  ["--resume-all", "-E", GetoptLong::NO_ARGUMENT],
  ["--report", "-r", GetoptLong::REQUIRED_ARGUMENT],
  ["--output", "-o", GetoptLong::REQUIRED_ARGUMENT],
  ["--output1", "-1", GetoptLong::REQUIRED_ARGUMENT]
)

def give_error
  $stderr.print "You used incompatible options, probably you mixed --scan with --stop"
  $stderr.print "or something similar."
  exit 0
end

opt.each do |opt,arg|
  case opt
    when	'--help'
      give_help
    when	'--user'
      user = arg
    when	'--password'
      password = arg
    when 	'--stop'
      if operation == ''
        operation = "stop"
        scanname = arg
      else
        give_error
      end
    when 	'--pause'
      if operation == ''
        operation = "pause"
        scanname = arg
      else
        give_error
      end
    when 	'--resume'
      if operation == ''
        operation = "resume"
        scanname = arg
      else
        give_error
      end
    when 	'--stop-all'
      if operation == ''
        operation = "stop-all"
      else
        give_error
      end
    when 	'--pause-all'
      if operation == ''
        operation = "pause-all"
      else
        give_error
      end
    when 	'--resume-all'
      if operation == ''
        operation = "resume-all"
      else
        give_error
      end
    when 	'--report'
      if operation == ''
        operation = "report"
        scanname = arg
      else
        give_error
      end
    when 	'--scan'
      if operation == ''
        operation = "scan"
        scanname = arg
      else
        give_error
      end
    when	'--target'
      if arg[0..6] == 'file://'
        f = File.open(arg[7..-1], "r")
        f.each_line do |line|
          line=line.chomp
          line=line.strip
          unless line == '' or line == nil
            if targets == ''
              targets = line
            else
              targets = targets + "," + line
            end
          end
        end
        f.close
      else
        # if there's multiple target options, add comma
        if targets == ''
          targets = arg
        else
          targets = targets + "," + arg
        end
      end
    when	'--wait'
      if arg == ''
        wait = 15
      else
        wait = arg.to_i
      end
    when	'--reportdelete'
      if arg == ''
        deletereport=true
      else
        operation = "reportdelete"
        scanname = arg
      end
    when	'--output'
      output = arg
    when	'--output1'
      output1 = arg
    when	'--policy'
      policy = arg
    when	'--status'
      if operation == ''
        operation = "status"
        scanname = arg
      else
        give_error
      end
    when	'--details'
      if operation == ''
        operation = "details"
        scanname = arg
      else
        give_error
      end
    when	'--add-targets'
      if operation == ''
        operation = "configure"
        scanname = arg
        
      else
        give_error
      end
    when	'--url'
      url = arg
    when 	'--verbose'
      if arg == ''
        verbose += 1
      else
        verbose = arg.to_i
      end
    when 	'--debug'
      if arg == ''
        debug += 1
      else
        debug = arg.to_i
      end
    when	'--list-scans'
      if operation == ''
        operation = "list-scans"
        scanname = arg
      else
        give_error
      end
    when	'--list-policy'
      if operation == ''
        operation = "list-policy"
        scanname = arg
      else
        give_error
      end
  end 
end 

if (user == '') or (password == '')
  $stderr.print "User and password is required to login to Nessus server"
  $stderr.print "Try --help!"
  exit 1
end 

$stderr.print "[i] Targets: " + targets +"\n" if verbose > 0 
$stderr.print "[i] Connecting to nessus server: " if verbose > 0 
n=NessusClient::Nessus6API.new(url,user,password)

if n.login(user, password)
  $stderr.print "OK!\n" if verbose > 0
else
  $stderr.print "[e] Error connecting/logging to the server!\n" 
  exit 2
end

case operation
  when "scan"
    if policy == ''
      $stderr.print "[w] Policy not defined, please specify a policy name. If you do not know policy name, run 'list-policy' command.\n"
	  exit 1
    else
	  pid=n.policy_get_id(policy)
      if pid == ''
		$stderr.print "[e] policy doesn't exit: " + policy + "\n"
		exit 1			
	  end
    end	
    if targets == ''
      $stderr.print "[w] Targets not defined, please specify the server(s) to scan\n"
      exit 1
    end

    $stderr.print "[i] Initiating scan with targets: "+targets+': ' if verbose > 0
    #uid=n.scan_new(pid,scanname,targets)
    uid=n.scan_create(uuid,pid,scanname,targets)
    $stderr.print "done\n" if verbose > 0

    scanid="#{uid['scan']['id']}"
    puts "Scan launched: #{uid['scan']['name']}\t Scan ID: #{uid['scan']['id']}"    
    if scanid ==''
      puts "scanid is blank\n"
      exit 1
    else
      n.scan_launch(scanid)
      exit 0
    end

=begin
    #n.scan_launch(uid)
    unless wait == ''
      #while not n.scan_finished(uid)
      while not n.scan_status(uid)
        $stderr.print "[v] Sleeping for " + wait.to_s() + ": " if verbose > 1			
        sleep wait
        $stderr.print "done\n" if verbose > 1
        stat = n.scan_status(uid)
        print "\r" + stat if verbose > 0
      end	
    else
      puts uid
      n.scan_launch(uid)
      exit 0
    end
	
    unless output == ''
      $stderr.print "[i] Output XML report to file: "+output if verbose > 0
      content=n.report_file_download(uid)	
      File.open(output, 'w') {|f| f.write(content) }	
      $stderr.print ": done\n" if verbose > 0
    end
    unless output1 == ''
      $stderr.print "[i] Output XML1 report to file: "+output1 if verbose > 0
      content=n.report_file1_download(uid)	
      File.open(output, 'w') {|f| f.write(content) }	
      $stderr.print ": done\n" if verbose > 0
    end
    if deletereport
      $stderr.print "[i] Deleting report: " if verbose > 0
      n.report_delete(uid)
      $stderr.print "done\n" if verbose > 0
    end
=end

  when "report"
    uid=scanname
    if (output == '') and (output1 == '') 
      $stderr.print "[e] You want report, but specify filename with --output or output1\n"
    end
    unless output == ''
      $stderr.print "[i] Output XML report to file: "+output if verbose > 0
      content=n.report_file_download(uid)	
      File.open(output, 'w') {|f| f.write(content) }	
      $stderr.print ": done\n" if verbose > 0
    end
    unless output1 == ''
      $stderr.print "[i] Output XML1 report to file: "+output1 if verbose > 0
      content=n.report1_file_download(uid)	
      File.open(output, 'w') {|f| f.write(content) }	
      $stderr.print ": done\n" if verbose > 0
    end
    if deletereport
      $stderr.print "[i] Deleting report: " if verbose > 0
      n.report_delete(uid)
      $stderr.print "done\n" if verbose > 0
    end
  when "stop"
    $stderr.print "[i] Stopping scan: " + scanname if verbose > 0
    n.scan_stop(scanname)
    $stderr.print "done\n" if verbose > 0
  when "stop-all"
    $stderr.print "[i] Stopping all scans: " if verbose > 0	
    list=n.scan_stop_all
    $stderr.print "done\n" if verbose > 0
    if verbose > 1
      list.each {|uuid| puts "[v] Stop all: " + uuid }
    end
  when "pause"
    $stderr.print "[i] Pausing scan: " + scanname if verbose > 0
    n.scan_pause(scanname)
    $stderr.print "done\n" if verbose > 0
  when "pause-all"
    $stderr.print "[i] Pausing all scans: " if verbose > 0	
    list=n.scan_pause_all
    $stderr.print "done\n" if verbose > 0
    if verbose > 1
      list.each {|uuid| puts "[v] Pause all: " + uuid }
    end
  when "resume"
    $stderr.print "[i] Resuming scan: " + scanname if verbose > 0
    n.scan_resume(scanname)
    $stderr.print "done\n" if verbose > 0
  when "resume-all"
    $stderr.print "[i] Resuming all scans: " if verbose > 0	
    list=n.scan_resume_all
    $stderr.print "done\n" if verbose > 0
    if verbose > 1
      list.each {|uuid| puts "[v] Resume all: " + uuid }
    end
  when "reportdelete"
    $stderr.print "[i] Deleting report: " + scanname if verbose > 0
    n.report_delete(scanname)
    $stderr.print "done\n" if verbose > 0
  when "status"
    puts "Status: #{n.scan_status(scanname)}"
  when "details"
    puts "Scan details: #{n.scan_details(scanname)}"       
  when "configure"
    puts "Adding targets: #{n.scan_configure(scanname)}"        
  when "list-scans"
    list=n.scan_list
    puts "\nScan Name\t\tScan ID\tSchedule"
    list['scans'].each do |scan|
	  puts scan
	  puts "#{scan['name']}\t#{scan['id']}\t#{scan['rrules']}"
	  puts "\n"
    end
  when "list-policy"
    list=n.list_policies
    puts "\nPolicy Name\t\tPolicy ID"
    list['policies'].each do |policy|
      puts "#{policy['name']}\t#{policy['id']}"
    end
end 

$stderr.print "[v] End reached.\n" if verbose > 1
### Venkat
