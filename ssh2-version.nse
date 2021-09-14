local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local stdnse = require "stdnse"
local table = require "table"
local match = require "match"


description = [[ Reports the version of the target SSH2 server ]]
categories = {"version"}
author = "Pranav Sivvam"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

portrule = shortport.ssh

action = function(host, port)
	local sock = nmap.new_socket()
	local status = sock:connect(host, port)
	if not status then
		sock:close()
		return
	end
	local status, data = sock:receive_buf("\r?\n", false)
	if not status then
		sock:close()
		return
	end
	local output = stdnse.output_table()
	output.version = data
	return output
end
