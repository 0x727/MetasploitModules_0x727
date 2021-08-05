
require 'msf/core'
class MetasploitModule < Msf::Auxiliary
include Msf::Exploit::Remote::Tcp
include Msf::Auxiliary::Scanner
    def initialize
        super(
        'Name' => 'Discover Windows Interface Address',
        'Version'        => '$Revision: 1 $',
        'Description'    => 'Find the host network card address through OXID Resolver',
        'Author'         => 'Rvn0xsy',
        'License'        => MSF_LICENSE
        )
        register_options(
        [
            Opt::RPORT(135),
            OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000])
        ], self.class)
    end

    def run_host(ip)
        timeout = datastore['TIMEOUT'].to_i
        sock = connect(false,
            {
                'RPORT' => 135,
                'RHOST' => ip,
                'ConnectTimeout' => (timeout / 1000.0)
            }
        )
        if sock
            print_good("#{ip}:#{rport} - TCP OPEN")
        end
        begin
        rescue ::Rex::ConnectionRefused
            vprint_status("#{ip}:#{port} - TCP closed")
        rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
        rescue ::Rex::Post::Meterpreter::RequestError
        rescue ::Timeout::Error
        rescue ::Interrupt
            raise $!
        rescue ::Exception => e
            vprint_status("#{ip}:#{port} exception #{e.class} #{e} #{e.backtrace}")
        ensure
            if sock == nil
                disconnect(sock) rescue nil
                return
            end
        end
        pack_v1 = "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00" 
        pack_v2 = "\x05\x00\x00\x03\x10\x00\x00\x00\x18\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00"
        sock.puts(pack_v1)
        data = sock.recv(1024)
        sock.puts(pack_v2)
        data = sock.recv(1024)
        packet_v1 = data[42..-1]
        packet_v2_end = packet_v1.index("\x09\x00\xff\xff\x00\x00") - 1
        packet_v2 = packet_v1[0..packet_v2_end]
        hostname_list = packet_v2.split("\x00\x00")
        for host in hostname_list do
            #r = "\x07\x00"
            host = host.sub("\x07\x00",'')
            host = host.sub("\x00",'')
            # host.split(//).each {|h|; print (h.unpack('H*').to_s + "\n")}
            host = host.sub("\x00",'')
            if host == ""
                next
            end
            print_good("#{host}")
        end
        print_status("Received: #{data.length} Bytes from #{ip}")
        disconnect()
    end
end