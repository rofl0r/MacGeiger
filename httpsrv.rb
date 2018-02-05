require 'socket'
require 'json'
require 'stringio'

$docroot = "./web"
$port = 8080

$macgeigerport = 9876

$wifis = Hash.new
def wifi_gather
	socket = TCPSocket.new 'localhost', $macgeigerport
	out = false
	loop do
		socket.puts "LIST\n"
		loop do
			line = socket.gets
			if line == nil then
				out = true
				break
			elsif line == "END\n" then
				break
			end
			wifi_hash = JSON.parse(line)
			#if wifis.key?(wifi_hash["bssid"])
			$wifis[wifi_hash["bssid"]] = line.chomp
		end
		if out then
			break
		end
		sleep 1
	end
	socket.close
end

def select_mac(mac)
	socket = TCPSocket.new 'localhost', $macgeigerport
	socket.puts "SELECT " + mac
	socket.close
end

def unselect_mac()
	socket = TCPSocket.new 'localhost', $macgeigerport
	socket.puts "UNSELECT"
	socket.close
end

def http_resp(skt, status, io, content_type)
	io.rewind
	skt.print "HTTP/1.1 #{status}\r\nContent-Type: #{content_type}\r\n" +
		"Content-Length: #{io.size}\r\nConnection: keep-alive\r\n"+
		"\r\n"
	IO.copy_stream(io, skt)
end

CONTENT_TYPE_MAPPING = {
	'html' => 'text/html',
	'txt' => 'text/plain',
	'png' => 'image/png',
	'jpg' => 'image/jpeg',
	'css' => 'text/css',
	'js' => 'text/javascript',
	'json' => 'application/json',
}

def content_type(path)
  ext = File.extname(path).split(".").last
  CONTENT_TYPE_MAPPING.fetch(ext, 'application/octet-stream')
end


def serve_static(socket, url)
	url = '/index.html' if url == '/'
	ct = content_type(url)
	path = $docroot + url
	if !(File.exist?(path) && !File.directory?(path)) || url.include?("..")
		io = StringIO.new
		io.puts "File not found"
		http_resp socket, "404 Not Found", io, "text/plain"
	else
		File.open(path, "rb") do |file|
			http_resp socket, "200 OK", file, ct
		end
	end
end

def serve_full(skt)
	io = StringIO.new
	io.puts '{"wifis" : ['
	#thanks to json's stupid decision that no trailing commas are accepted!
	n = $wifis.size
	i = 0
	$wifis.each do |wifi, json|
		io.print json
		i += 1
		if i != n then
			io.print ","
		end
		io.print "\n"
	end
	io.print "]}\n"
	http_resp(skt, "200 OK", io, "application/json")
end

def serve_empty(skt)
	io = StringIO.new
	http_resp(skt, "200 OK", io, "text/html")
end

def serve_update(skt)
	skt.puts "full"
end

def get_path(str)
	x = str.split(" ")
	if x[0] == "GET" then
		return x[1]
	end
	return nil
end

class Client
	def initialize
		@running = false
		@socket = nil
		@th  = nil
	end

	def assign_thread(th)
		@th = th
	end

	def running?
		@running
	end

	def jointhr
		@th.join
	end

	def run(socket)
		@running = true
		@socket = socket
		loop do
			line = socket.gets
			if line == nil then
				break
			end
			url = get_path(line)
			if url == nil then
			elsif url == "/api/unselect" then
				unselect_mac()
				serve_empty(@socket)
			elsif url.start_with?("/api/select/") then
				mac = url.split("/").last
				select_mac (mac)
				serve_empty(@socket)
			elsif url.start_with?("/api/") then
				case url
				when "/api/full"
					serve_full(@socket)
				when "/api/update"
					serve_update(@socket)
				else
					puts url
				end
			else
				serve_static(@socket, url)
			end
		end
		@socket.close
		@running = false
	end
end


gt = Thread.new { wifi_gather }

server = TCPServer.new $port

clients = []
while session = server.accept
	clients.each do |client|
		if not client.running? then
			client.jointhr
		end
	end
	client = Client.new
	client.assign_thread ( Thread.new {client.run(session)} )
	clients << client
end

gt.join
