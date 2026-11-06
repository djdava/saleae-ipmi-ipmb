"""Saleae Logic 2 HLA: built-in I2C frames -> one annotation per IPMB message."""

from saleae.analyzers import AnalyzerFrame, ChoicesSetting, HighLevelAnalyzer

from ipmb import decode_message
from payloads import decode_payload


class Hla(HighLevelAnalyzer):
    display = ChoicesSetting(choices=['Compact', 'Detailed'])
    payload_view = ChoicesSetting(
        choices=['Inspector only', 'Decoded summary', 'Hex bytes'], label='Payload display')
    result_types = {
        'request': {'format': '{{data.label}}'},
        'response': {'format': '{{data.label}}'},
        'response_error': {'format': '{{data.label}}'},
        'warning': {'format': '{{data.label}}'},
    }
    # Safety limit, not an assertion of a permitted IPMB protocol length.
    MAX_BYTES = 1024
    MAX_PENDING = 128
    MATCH_WINDOW_S = 5.0

    def __init__(self):
        self.pending = {}
        self._reset()

    def _reset(self, start=None):
        self.start = start
        self.end = start
        self.raw = []
        self.warnings = []
        self.have_address = False
        self.read = False

    def _finish(self, termination):
        if not self.raw and not self.warnings:
            return None
        warnings = list(self.warnings)
        message = None if self.read else decode_message(self.raw)
        if message is None:
            label = 'Not IPMB (I2C read)' if self.read else 'Incomplete IPMB'
            if warnings:
                label += ' [' + '; '.join(warnings) + ']'
            data = {'label': label, 'raw': bytes(self.raw).hex(' '),
                    'warnings': '; '.join(warnings), 'termination': termination}
            return AnalyzerFrame('warning', self.start, self.end, data)

        warnings.extend(message.pop('warnings'))
        request, match, latency = self._request_context(message, trusted=not warnings)
        payload = decode_payload(message, request, trusted=not warnings)
        direction = 'RSP' if message['response'] else 'REQ'
        if message['broadcast']:
            direction = 'BROADCAST ' + direction
        if message['response']:
            direction += ': %s (0x%02X)' % (message['completion'], message['completion_code'])
        label = '%s [%s]' % (message['name'], direction)
        if self.display == 'Detailed':
            label += ' 0x%02X -> 0x%02X seq=%d' % (
                message['source_ipmb'], message['destination_ipmb'], message['sequence'])
        if self.payload_view == 'Decoded summary':
            text = payload['summary']
            if not text and message['payload'] and payload['status'] != 'decoded':
                text = 'data: ' + message['payload']
            if payload['status'] == 'malformed':
                text = 'INVALID PAYLOAD; ' + text
            if text:
                label += ' | ' + self._preview(text)
        elif self.payload_view == 'Hex bytes' and message['payload']:
            label += ' | data: ' + self._preview(message['payload'])
        if warnings:
            label = 'UNVERIFIED: ' + label + ' [' + '; '.join(warnings) + ']'
        kind = 'request'
        if message['response']:
            kind = 'response_error' if message['completion_code'] else 'response'
        if warnings:
            kind = 'warning'
        # AnalyzerFrame data uses scalar values, also available in the data table.
        message['completion_code'] = (message['completion_code']
                                      if message['response'] else '')
        message.update(payload_summary=payload['summary'], payload_status=payload['status'],
                       payload_notes=payload['notes'], request_match=match,
                       response_latency_ms=latency,
                       decoded='; '.join('%s=%s' % item for item in payload['fields'].items()))
        message.update(('field_' + key, value) for key, value in payload['fields'].items())
        message.update(label=label, warnings='; '.join(warnings), termination=termination)
        return AnalyzerFrame(kind, self.start, self.end, message)

    @staticmethod
    def _preview(text):
        # Limit waveform clutter only; table/export fields keep the full data.
        return text if len(text) <= 120 else text[:117] + '...'

    @staticmethod
    def _request_key(message, reverse=False):
        source, destination = message['source_ipmb'], message['destination_ipmb']
        source_lun, destination_lun = message['source_lun'], message['destination_lun']
        if reverse:
            source, destination = destination, source
            source_lun, destination_lun = destination_lun, source_lun
        netfn = message['netfn'] & ~1
        data = bytes.fromhex(message['payload'])
        prefix = data[:1] if netfn == 0x2C else data[:3] if netfn == 0x2E else b''
        return (netfn, message['command'], source, destination, source_lun,
                destination_lun, message['sequence'], prefix)

    def _request_context(self, message, trusted):
        # Cache is per HLA instance/capture, bounded by age and count. It stores
        # only complete transport-valid requests; no global device assumptions.
        for key, (start, _, _) in list(self.pending.items()):
            age = float(self.start - start)
            if age < 0 or age > self.MATCH_WINDOW_S:
                del self.pending[key]
        if not trusted or message['broadcast']:
            return None, 'untrusted' if not trusted else 'not_applicable', ''
        key = self._request_key(message, reverse=message['response'])
        if message['response']:
            item = self.pending.pop(key, None)
            if item is None:
                return None, 'unmatched', ''
            start, request, ambiguous = item
            if ambiguous:
                return None, 'ambiguous', ''
            return request, 'matched', float(self.start - start) * 1000
        previous = self.pending.pop(key, None)
        ambiguous = bool(previous and (previous[2] or previous[1]['payload'] != message['payload']))
        self.pending[key] = (self.start, dict(message), ambiguous)
        while len(self.pending) > self.MAX_PENDING:
            del self.pending[next(iter(self.pending))]
        return None, 'not_applicable', ''

    def decode(self, frame):
        if frame.type == 'start':
            previous = self._finish('repeated_start')
            self._reset(frame.start_time)
            return previous

        if frame.type == 'address':
            # Also recover if capture starts with an address rather than START.
            previous = None
            if self.have_address:
                self.warnings.append('address without START')
                previous = self._finish('address')
                self._reset(frame.start_time)
            if self.start is None:
                self.start = frame.start_time
            self.have_address = True
            self.read = frame.data['read']
            self.raw.append((frame.data['address'][0] << 1) | int(self.read))
            self.end = frame.end_time
            self._check_frame(frame, 0)
            return previous

        if frame.type == 'data' and self.have_address:
            self.end = frame.end_time
            if len(self.raw) >= self.MAX_BYTES:
                self.warnings.append('buffer limit exceeded')
                result = self._finish('buffer_limit')
                self._reset()
                return result
            self.raw.append(frame.data['data'][0])
            self._check_frame(frame, len(self.raw) - 1)
        elif frame.type == 'stop':
            self.end = frame.end_time
            result = self._finish('stop')
            self._reset()
            return result
        elif frame.type not in ('data',):
            if self.start is not None:
                self.warnings.append('unexpected I2C frame: ' + frame.type)

    def _check_frame(self, frame, index):
        if not frame.data.get('ack', True):
            self.warnings.append('NACK address' if index == 0 else 'NACK byte %d' % index)
        if frame.data.get('error'):
            self.warnings.append('I2C error: ' + str(frame.data['error']))
