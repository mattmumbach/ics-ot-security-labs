# ICS/OT lab 01: Modbus detections D1-D3 for Zeek 9.0.1.
# Event signatures checked against the installed image:
#   /usr/local/zeek/share/zeek/base/bif/plugins/Zeek_Modbus.events.bif.zeek
#
# D1  Unauthorized Modbus write: any write function code from a host other than the EWS.
# D2  Unsafe setpoint: a write that puts holding register 0 outside 40-60, from any host.
# D3  Recon: Read Device Identification (FC 43, MEI type 14) from a host other than the EWS.

module ICS;

export {
    redef enum Notice::Type += {
        Unauthorized_Modbus_Write,   # D1
        Unsafe_Setpoint,             # D2
        Modbus_Device_Recon,         # D3
    };

    # Hosts allowed to send writes: the engineering workstation only.
    option authorized_writers: set[addr] = { 172.20.0.30 };

    # Function codes that change PLC state. 5, 6, 15 and 16 are the coil and register
    # writes; 21 (write file record), 22 (mask write register) and 23 (read/write
    # multiple registers) also write, so they are included.
    option write_fcs: set[count] = { 5, 6, 15, 16, 21, 22, 23 };

    # The process setpoint and its safe range.
    option setpoint_register: count = 0;
    option setpoint_min: count = 40;
    option setpoint_max: count = 60;
}

# D1: every Modbus message passes through here; is_orig is T for the client's request.
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
    {
    if ( ! is_orig )
        return;
    if ( headers$function_code in write_fcs && c$id$orig_h !in authorized_writers )
        NOTICE([$note=Unauthorized_Modbus_Write, $conn=c,
                $msg=fmt("Modbus write (FC %d) from %s, which is not an authorized writer",
                         headers$function_code, c$id$orig_h),
                $sub=fmt("FC %d", headers$function_code)]);
    }

function check_setpoint(c: connection, fc: count, value: count)
    {
    if ( value < setpoint_min || value > setpoint_max )
        NOTICE([$note=Unsafe_Setpoint, $conn=c,
                $msg=fmt("Setpoint (register %d) written as %d by %s; safe range is %d-%d",
                         setpoint_register, value, c$id$orig_h, setpoint_min, setpoint_max),
                $sub=fmt("FC %d value %d", fc, value)]);
    }

# D2, FC 6: one register.
event modbus_write_single_register_request(c: connection, headers: ModbusHeaders,
                                           address: count, value: count)
    {
    if ( address == setpoint_register )
        check_setpoint(c, 6, value);
    }

# D2, FC 16: a block of registers; check it only if the block covers the setpoint.
event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders,
                                              start_address: count, registers: ModbusRegisters)
    {
    if ( setpoint_register >= start_address &&
         setpoint_register < start_address + |registers| )
        check_setpoint(c, 16, registers[setpoint_register - start_address]);
    }

# D3: FC 43 with MEI type 14 is Read Device Identification (vendor, product, version).
event modbus_encap_interface_transport_request(c: connection, headers: ModbusHeaders,
                                               mei_type: count, data: string)
    {
    if ( mei_type == 14 && c$id$orig_h !in authorized_writers )
        NOTICE([$note=Modbus_Device_Recon, $conn=c,
                $msg=fmt("Read Device Identification (FC 43/14) from %s", c$id$orig_h)]);
    }
