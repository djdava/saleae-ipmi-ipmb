"""Selected IPMI/PICMG payload fields; no FRU/SDR reassembly or sensor scaling.

Integer byte order and field layouts follow the references in README.md.
Unknown, short, unsuccessful or untrusted messages retain their raw payload.
"""


class ShortPayload(ValueError):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.fields = {}

    def take(self, count):
        end = self.offset + count
        if end > len(self.data):
            raise ShortPayload('need at least %d bytes, got %d' % (end, len(self.data)))
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def integer(self, name, count=1):
        value = int.from_bytes(self.take(count), 'little')
        self.fields[name] = value
        return value

    def blob(self, name, count=None):
        value = self.take(len(self.data) - self.offset if count is None else count)
        self.fields[name] = value.hex(' ')
        return value


def _device_id(r, response, request):
    if not response:
        return ''
    device = r.integer('device_id')
    revision = r.integer('device_revision_raw')
    major = r.integer('firmware_major_raw')
    minor = r.integer('firmware_minor_bcd')
    version = r.integer('ipmi_version_raw')
    support = r.integer('device_support_mask')
    r.integer('manufacturer_id', 3)
    r.integer('product_id', 2)
    if len(r.data) > r.offset:
        r.blob('auxiliary_firmware_revision', 4)
    # Minor firmware revision is packed BCD; do not label non-BCD bytes as decimal.
    minor_text = '%02X' % minor
    if minor >> 4 > 9 or minor & 15 > 9:
        minor_text = '0x%02X (invalid BCD)' % minor
    firmware = '%d.%s' % (major & 0x7F, minor_text)
    ipmi = '%d.%d' % (version & 15, version >> 4)
    r.fields.update(device_revision=revision & 15, provides_device_sdr=bool(revision & 0x80),
                    device_available=not bool(major & 0x80), firmware=firmware, ipmi_version=ipmi)
    capabilities = ['sensor', 'SDR', 'SEL', 'FRU', 'IPMB event receiver',
                    'IPMB event generator', 'bridge', 'chassis']
    r.fields['device_support'] = ', '.join(name for bit, name in enumerate(capabilities)
                                          if support & (1 << bit)) or 'none'
    return 'device=%d; FW %s; IPMI %s' % (device, firmware, ipmi)


def _event_receiver(r, response, request):
    # Set has data only in the request; Get has data only in the response.
    address = r.integer('event_receiver_ipmb')
    lun = r.integer('event_receiver_lun_raw')
    r.fields['event_receiver_lun'] = lun & 3
    r.fields['event_generation_disabled'] = address == 0xFF
    return 'receiver=0x%02X; LUN=%d%s' % (
        address, lun & 3, ' (events disabled)' if address == 0xFF else '')


def _platform_event(r, response, request):
    if response:
        return ''
    r.integer('event_message_revision')
    sensor_type = r.integer('sensor_type')
    sensor = r.integer('sensor_number')
    event = r.integer('event_direction_type_raw')
    r.fields.update(event_direction='deassertion' if event & 0x80 else 'assertion',
                    event_type=event & 0x7F)
    r.blob('event_data', 3)
    return 'sensor=%d; type=0x%02X; %s' % (sensor, sensor_type, r.fields['event_direction'])


def _fru_info(r, response, request):
    if not response:
        return 'FRU=%d' % r.integer('fru_id')
    size = r.integer('inventory_size_bytes', 2)
    mode = r.integer('access_mode_raw')
    r.fields['access_mode'] = 'words' if mode & 1 else 'bytes'
    return 'size=%d bytes; access=%s' % (size, r.fields['access_mode'])


def _read_fru(r, response, request):
    if not response:
        fru = r.integer('fru_id')
        offset = r.integer('offset', 2)
        count = r.integer('requested_count')
        return 'FRU=%d; offset=%d; count=%d' % (fru, offset, count)
    count = r.integer('returned_count')
    data = r.blob('fru_data')
    # Count is in bytes, even when the request offset is word-addressed.
    if count != len(data):
        raise ValueError('FRU returned count %d differs from data length %d' % (count, len(data)))
    return 'returned=%d bytes; data=%s' % (count, data.hex(' '))


def _write_fru(r, response, request):
    if response:
        return 'written=%d bytes' % r.integer('written_count')
    fru = r.integer('fru_id')
    offset = r.integer('offset', 2)
    data = r.blob('fru_data')
    return 'FRU=%d; offset=%d; write=%d bytes' % (fru, offset, len(data))


def _device_sdr_info(r, response, request):
    if not response:
        selector = r.integer('count_selector') if r.data else 0
        r.fields['count_selector'] = selector
        return 'count=%s' % ('SDRs' if selector & 1 else 'sensors')
    count = r.integer('count')
    flags = r.integer('population_flags')
    r.fields.update(dynamic_population=bool(flags & 0x80), sensor_lun_mask=flags & 15)
    if flags & 0x80:
        r.integer('population_change_indicator', 4)
    # Without the request selector, the first byte cannot be called sensor count.
    kind = 'count'
    if request is not None:
        kind = 'SDRs' if request and request[0] & 1 else 'sensors'
    r.fields['count_kind'] = kind
    return '%s=%d; %s population' % (kind, count, 'dynamic' if flags & 0x80 else 'static')


def _reserve_sdr(r, response, request):
    return 'reservation=%d' % r.integer('reservation_id', 2) if response else ''


def _get_sdr(r, response, request):
    if not response:
        reservation = r.integer('reservation_id', 2)
        record = r.integer('record_id', 2)
        offset = r.integer('offset')
        count = r.integer('requested_count')
        return 'record=0x%04X; offset=%d; count=%s; reservation=%d' % (
            record, offset, 'all' if count == 0xFF else count, reservation)
    next_record = r.integer('next_record_id', 2)
    data = r.blob('record_data')
    # A fragment is NOT a complete SDR. Never assume offset zero without context.
    return 'next=0x%04X%s; fragment=%d bytes; data=%s' % (
        next_record, ' (end)' if next_record == 0xFFFF else '', len(data), data.hex(' '))


def _sensor_reading(r, response, request):
    if not response:
        return 'sensor=%d' % r.integer('sensor_number')
    raw = r.integer('reading_raw')
    flags = r.integer('reading_flags')
    unavailable = bool(flags & 0x20)
    r.fields.update(reading_available=not unavailable, scanning_enabled=bool(flags & 0x40),
                    events_enabled=bool(flags & 0x80))
    r.blob('state_bytes')
    # Threshold vs discrete status and engineering units require sensor metadata.
    return 'reading unavailable' if unavailable else 'raw=0x%02X (unscaled)' % raw


COLORS = {0: 'unsupported', 1: 'blue', 2: 'red', 3: 'green', 4: 'amber',
          5: 'orange', 6: 'white', 14: 'unchanged', 15: 'default'}


def _led_state(r, prefix):
    function = r.integer(prefix + 'function')
    duration = r.integer(prefix + 'on_duration_raw')
    color = r.integer(prefix + 'color_raw') & 15
    names = {0: 'off', 0xFB: 'lamp test', 0xFC: 'restore local control',
             0xFD: 'reserved', 0xFE: 'reserved', 0xFF: 'on'}
    name = names.get(function, 'blink')
    r.fields[prefix + 'mode'] = name
    r.fields[prefix + 'color'] = COLORS.get(color, 'reserved')
    if 1 <= function <= 0xFA:
        r.fields[prefix + 'off_duration_ms'] = function * 10
        r.fields[prefix + 'on_duration_ms'] = duration * 10
    return '%s %s' % (r.fields[prefix + 'color'], name)


def _picmg_properties(r, response, request):
    if not response:
        return ''
    version = r.integer('picmg_version_raw')
    maximum = r.integer('max_fru_id')
    fru = r.integer('fru_id')
    r.fields['picmg_version'] = '%d.%d' % (version & 15, version >> 4)
    return 'PICMG %s; FRU=%d; max FRU=%d' % (r.fields['picmg_version'], fru, maximum)


def _fru_control(r, response, request):
    if response:
        return ''
    fru = r.integer('fru_id')
    control = r.integer('control')
    names = {0: 'cold reset', 1: 'warm reset', 2: 'graceful reboot',
             3: 'diagnostic interrupt', 4: 'quiesce'}
    r.fields['control_name'] = names.get(control, 'reserved/OEM')
    return 'FRU=%d; %s (0x%02X)' % (fru, r.fields['control_name'], control)


def _led_properties(r, response, request):
    if not response:
        return 'FRU=%d' % r.integer('fru_id')
    r.integer('general_led_mask')
    return 'application LEDs=%d' % r.integer('application_led_count')


def _fru_led_request(r):
    fru = r.integer('fru_id')
    led = r.integer('led_id')
    return 'FRU=%d; LED=%d' % (fru, led)


def _led_colors(r, response, request):
    if not response:
        return _fru_led_request(r)
    mask = r.integer('color_capability_mask')
    local = r.integer('default_local_color_raw') & 15
    override = r.integer('default_override_color_raw') & 15
    r.fields.update(supported_colors=', '.join(COLORS[bit] for bit in range(1, 7)
                                               if mask & (1 << bit)) or 'none',
                    default_local_color=COLORS.get(local, 'reserved'),
                    default_override_color=COLORS.get(override, 'reserved'))
    return 'colors=%s' % r.fields['supported_colors']


def _set_led(r, response, request):
    if response:
        return ''
    target = _fru_led_request(r)
    return target + '; ' + _led_state(r, 'led_')


def _get_led(r, response, request):
    if not response:
        return _fru_led_request(r)
    flags = r.integer('led_state_flags')
    r.fields.update(local_control=bool(flags & 1), override_active=bool(flags & 2),
                    lamp_test_active=bool(flags & 4))
    states = ['local: ' + _led_state(r, 'local_')]
    if flags & 6 or len(r.data) - r.offset >= 3:
        states.append('override: ' + _led_state(r, 'override_'))
    if flags & 4 or len(r.data) - r.offset:
        r.integer('lamp_test_duration_raw')
    return '; '.join(states)


def _set_policy(r, response, request):
    if response:
        return ''
    fru = r.integer('fru_id')
    mask = r.integer('policy_mask')
    bits = r.integer('policy_bits')
    return 'FRU=%d; policy mask=0x%02X; bits=0x%02X' % (fru, mask, bits)


def _get_policy(r, response, request):
    if not response:
        return 'FRU=%d' % r.integer('fru_id')
    bits = r.integer('policy_bits')
    r.fields.update(activation_locked=bool(bits & 1), deactivation_locked=bool(bits & 2))
    return 'activation locked=%s; deactivation locked=%s' % (
        r.fields['activation_locked'], r.fields['deactivation_locked'])


def _activation(r, response, request):
    if response:
        return ''
    fru = r.integer('fru_id')
    state = r.integer('activation_state')
    name = {0: 'deactivate', 1: 'activate'}.get(state, 'reserved')
    r.fields['activation_action'] = name
    return 'FRU=%d; %s' % (fru, name)


def _locator(r, response, request):
    if not response:
        return 'FRU=%d' % r.integer('fru_id')
    return 'record=0x%04X' % r.integer('record_id', 2)


# Set/Get Event Receiver share their data format, but on opposite directions.
DECODERS = {
    (0x06, 0x01): _device_id,
    (0x04, 0x00): lambda r, response, request: '' if response else _event_receiver(r, response, request),
    (0x04, 0x01): lambda r, response, request: _event_receiver(r, response, request) if response else '',
    (0x04, 0x02): _platform_event,
    (0x04, 0x20): _device_sdr_info,
    (0x04, 0x21): _get_sdr,
    (0x04, 0x22): _reserve_sdr,
    (0x04, 0x2D): _sensor_reading,
    (0x0A, 0x10): _fru_info,
    (0x0A, 0x11): _read_fru,
    (0x0A, 0x12): _write_fru,
    (0x0A, 0x22): _reserve_sdr,
    (0x0A, 0x23): _get_sdr,
    (0x2C, 0x00): _picmg_properties,
    (0x2C, 0x04): _fru_control,
    (0x2C, 0x05): _led_properties,
    (0x2C, 0x06): _led_colors,
    (0x2C, 0x07): _set_led,
    (0x2C, 0x08): _get_led,
    (0x2C, 0x0A): _set_policy,
    (0x2C, 0x0B): _get_policy,
    (0x2C, 0x0C): _activation,
    (0x2C, 0x0D): _locator,
}


def decode_payload(message, request=None, trusted=True):
    """Return summary, scalar fields, status and notes; never alter the message.

    Optional request context must already have been matched by the caller.
    Response completion codes are outside the payload; group IDs are inside it.
    """
    result = {'summary': '', 'fields': {}, 'status': 'raw', 'notes': ''}
    if not trusted or not message['checksum1_ok'] or not message['checksum2_ok']:
        result.update(status='untrusted', notes='Payload interpretation suppressed: integrity/transport warning')
        return result
    if message['response'] and message['completion_code'] != 0:
        result.update(status='response_error', notes='No success-payload interpretation for nonzero completion')
        return result
    key = (message['netfn'] & ~1, message['command'])
    data = bytes.fromhex(message['payload'])
    if key[0] == 0x2C:
        if not data or data[0] != 0:
            result['notes'] = 'Unsupported or missing Group Extension ID'
            return result
        data = data[1:]
    decoder = DECODERS.get(key)
    if decoder is None:
        result['notes'] = 'No payload decoder for this command'
        return result
    context = decode_payload(request) if request is not None else None
    if context is not None and context['status'] != 'decoded':
        context = None
    request_data = bytes.fromhex(request['payload']) if context is not None else None
    r = Reader(data)
    try:
        summary = decoder(r, message['response'], request_data)
    except (ShortPayload, ValueError) as error:
        result.update(status='malformed', notes=str(error))
        return result
    result.update(summary=summary, fields=r.fields, status='decoded')
    if r.offset < len(data):
        result.update(status='partial', notes='Trailing bytes not interpreted: ' + data[r.offset:].hex(' '))
    if key == (0x04, 0x2D) and message['response']:
        note = 'No engineering units or threshold/discrete interpretation without sensor metadata'
        result['notes'] = '; '.join(filter(None, [result['notes'], note]))
    if key in ((0x0A, 0x11), (0x0A, 0x12)):
        note = 'FRU offset is in access units; byte/word mode requires inventory metadata'
        result['notes'] = '; '.join(filter(None, [result['notes'], note]))
    # Only labels from a complete, successfully decoded request are inherited.
    if message['response'] and context is not None:
        for field in ('fru_id', 'led_id', 'sensor_number', 'record_id', 'offset', 'requested_count'):
            if field in context['fields']:
                result['fields']['request_' + field] = context['fields'][field]
        targets = ['%s=%s' % (name, context['fields'][field]) for name, field in
                   [('sensor', 'sensor_number'), ('FRU', 'fru_id'), ('LED', 'led_id')]
                   if field in context['fields']]
        if targets:
            result['summary'] = '; '.join(targets + ([summary] if summary else []))
    return result
