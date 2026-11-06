"""Transport-independent IPMB message decoding, compatible with Python 3.8."""

from commands import command_name, completion_name


def decode_message(raw):
    """Decode bytes including the wire address; return None if too short.

    Checksum failures are retained for diagnosis, not silently discarded.
    Broadcasts have a leading general-call byte before the destination address.
    """
    broadcast = bool(raw and raw[0] == 0)
    b = raw[1:] if broadcast else raw
    if len(b) < 7:
        return None
    netfn = b[1] >> 2
    response = bool(netfn & 1)
    if response and len(b) < 8:
        return None
    payload = b[7:-1] if response else b[6:-1]
    name, known = command_name(netfn, b[5], payload)
    warnings = []
    checksum1_ok = sum(b[:3]) % 256 == 0
    checksum2_ok = sum(b[3:]) % 256 == 0
    if not checksum1_ok:
        warnings.append('bad checksum 1')
    if not checksum2_ok:
        warnings.append('bad checksum 2')
    if b[0] & 1 or b[3] & 1:
        warnings.append('odd IPMB address')
    if broadcast and response:
        warnings.append('broadcast response')
    if (netfn & ~1) == 0x2C and not payload:
        warnings.append('missing group ID')
    if (netfn & ~1) == 0x2E and len(payload) < 3:
        warnings.append('missing OEM IANA ID')
    completion = b[6] if response else None
    return {
        'name': name, 'known': known, 'response': response,
        'broadcast': broadcast,
        'destination_ipmb': b[0], 'destination_i2c_7bit': b[0] >> 1,
        'source_ipmb': b[3], 'source_i2c_7bit': b[3] >> 1,
        'destination_lun': b[1] & 3, 'source_lun': b[4] & 3,
        'netfn': netfn, 'command': b[5], 'sequence': b[4] >> 2,
        'checksum1_ok': checksum1_ok, 'checksum2_ok': checksum2_ok,
        'completion_code': completion,
        'completion': completion_name(completion) if response else '',
        'payload': bytes(payload).hex(' '),
        'raw': bytes(raw).hex(' '), 'warnings': warnings,
    }
