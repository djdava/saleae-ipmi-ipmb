"""Synthetic protocol tests using a minimal Saleae API stub."""

import importlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


EXTENSION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EXTENSION))

from commands import PICMG, STANDARD, completion_name
from ipmb import decode_message


class Frame:
    def __init__(self, kind, start, end, data=None):
        self.type = kind
        self.start_time = start
        self.end_time = end
        self.data = data or {}


api = types.ModuleType('saleae.analyzers')
api.AnalyzerFrame = Frame
api.HighLevelAnalyzer = object
api.ChoicesSetting = lambda **kwargs: kwargs['choices'][0]
with patch.dict(sys.modules, {'saleae': types.ModuleType('saleae'), 'saleae.analyzers': api}):
    Hla = importlib.import_module('HighLevelAnalyzer').Hla


def message(netfn=6, command=1, payload=(), completion=0, destination=0x40,
            source=0x20, sequence=1, destination_lun=0, source_lun=0):
    head = [destination, (netfn << 2) | destination_lun]
    head.append(-sum(head) & 0xFF)
    body = [source, (sequence << 2) | source_lun, command]
    if netfn & 1:
        body.append(completion)
    body.extend(payload)
    return head + body + [-sum(body) & 0xFF]


def feed(hla, raw, acks=None, start=0, stop=True, read=False, errors=None):
    """Replay the documented Saleae I2C frame API, not digital transitions."""
    output = []
    acks = acks if acks is not None else [True] * len(raw)
    events = [Frame('start', start, start + 0.01)]
    for index, value in enumerate(raw):
        data = {'ack': acks[index]}
        if index == 0:
            data.update(address=bytes([value >> 1]), read=read)
        else:
            data['data'] = bytes([value])
        if errors and index in errors:
            data['error'] = errors[index]
        events.append(Frame('address' if index == 0 else 'data',
                            start + index + 0.1, start + index + 0.9, data))
    if stop:
        events.append(Frame('stop', start + len(raw), start + len(raw) + 0.01))
    for event in events:
        result = hla.decode(event)
        if result is not None:
            output.append(result)
    return output


class MessageTests(unittest.TestCase):
    def test_known_wire_vector(self):
        decoded = decode_message(bytes.fromhex('40 18 a8 20 04 01 db'))
        self.assertEqual(decoded['name'], 'Get Device ID')
        self.assertEqual(decoded['destination_i2c_7bit'], 0x20)
        self.assertEqual(decoded['source_ipmb'], 0x20)
        self.assertEqual(decoded['sequence'], 1)
        self.assertEqual(decoded['warnings'], [])

    def test_catalog_request_response_symmetry(self):
        for netfn, table in list(STANDARD.items()) + [(0x2C, PICMG)]:
            for command, name in table.items():
                for response in (0, 1):
                    with self.subTest(netfn=netfn, command=command, response=response):
                        raw = message(netfn | response, command,
                                      payload=[0] if netfn == 0x2C else [])
                        decoded = decode_message(raw)
                        self.assertEqual(decoded['name'], name)
                        self.assertTrue(decoded['known'])
                        self.assertEqual(decoded['warnings'], [])

    def test_group_is_not_automatically_picmg(self):
        decoded = decode_message(message(0x2C, 0, [0xDC]))
        self.assertFalse(decoded['known'])
        self.assertIn('Group 0xDC', decoded['name'])
        decoded = decode_message(message(0x2D, 0, [], completion=0xC1))
        self.assertFalse(decoded['known'])
        self.assertIn('missing group ID', decoded['warnings'])

    def test_unknown_and_oem(self):
        for netfn in (8, 0x2E, 0x30, 0x3E):
            decoded = decode_message(message(netfn, 0xFE, [0, 0, 0]))
            self.assertFalse(decoded['known'])
            self.assertIn('0xFE', decoded['name'])
            self.assertIn('0x%02X' % netfn, decoded['name'])
        self.assertIn('missing OEM IANA ID', decode_message(message(0x2E))['warnings'])

    def test_checksum_failures(self):
        for index, field in [(2, 'checksum1_ok'), (-1, 'checksum2_ok')]:
            raw = message()
            raw[index] ^= 1
            self.assertFalse(decode_message(raw)[field])

    def test_short_response_and_request(self):
        self.assertIsNone(decode_message(message()[:-1]))
        self.assertIsNone(decode_message(message(7)[:-1]))
        self.assertIsNone(decode_message([]))

    def test_broadcast(self):
        decoded = decode_message([0] + message())
        self.assertTrue(decoded['broadcast'])
        self.assertEqual(decoded['warnings'], [])
        self.assertEqual(decoded['destination_ipmb'], 0x40)

    def test_luns_sequence_and_completion(self):
        decoded = decode_message(message(7, completion=0xC0, sequence=63,
                                         destination_lun=2, source_lun=3))
        self.assertEqual(decoded['completion'], 'Node Busy')
        self.assertEqual(decoded['sequence'], 63)
        self.assertEqual(decoded['destination_lun'], 2)
        self.assertEqual(decoded['source_lun'], 3)
        self.assertEqual(completion_name(0x81), 'Command-specific completion')
        self.assertEqual(completion_name(1), 'OEM-specific completion')
        self.assertEqual(completion_name(0xFF), 'Unspecified Error')

    def test_odd_source_is_warned(self):
        self.assertIn('odd IPMB address', decode_message(message(source=0x21))['warnings'])


class HlaTests(unittest.TestCase):
    def test_annotation_and_times(self):
        result, = feed(Hla(), message())
        self.assertEqual(result.type, 'request')
        self.assertEqual(result.data['label'], 'Get Device ID [REQ]')
        self.assertEqual(result.data['raw'], '40 18 a8 20 04 01 db')
        self.assertEqual(result.start_time, 0)
        self.assertEqual(result.end_time, 7.01)

    def test_detailed(self):
        hla = Hla()
        hla.display = 'Detailed'
        result, = feed(hla, message())
        self.assertIn('0x20 -> 0x40 seq=1', result.data['label'])

    def test_responses(self):
        for code, kind in [(0, 'response'), (0xC0, 'response_error'), (0xCC, 'response_error')]:
            result, = feed(Hla(), message(7, completion=code))
            self.assertEqual(result.type, kind)
            self.assertIn('RSP:', result.data['label'])
            self.assertIn('0x%02X' % code, result.data['label'])

    def test_nack_address(self):
        result, = feed(Hla(), [0x40], [False])
        self.assertEqual(result.type, 'warning')
        self.assertIn('NACK address', result.data['label'])
        self.assertNotIn('Get Device ID', result.data['label'])

    def test_nack_data_and_i2c_error(self):
        acks = [True] * 7
        acks[-1] = False
        result, = feed(Hla(), message(), acks, errors={2: 'test error'})
        self.assertEqual(result.type, 'warning')
        self.assertTrue(result.data['label'].startswith('UNVERIFIED:'))
        self.assertIn('NACK byte 6', result.data['warnings'])
        self.assertIn('I2C error: test error', result.data['warnings'])

    def test_bad_checksum_is_not_silently_valid(self):
        raw = message()
        raw[-1] ^= 1
        result, = feed(Hla(), raw)
        self.assertEqual(result.type, 'warning')
        self.assertIn('UNVERIFIED', result.data['label'])

    def test_read_is_not_ipmb(self):
        result, = feed(Hla(), message(), read=True)
        self.assertEqual(result.type, 'warning')
        self.assertIn('Not IPMB', result.data['label'])

    def test_repeated_start_and_reset(self):
        hla = Hla()
        self.assertEqual(feed(hla, message(), stop=False), [])
        previous, result = feed(hla, message(7), start=10)
        self.assertEqual(previous.data['termination'], 'repeated_start')
        self.assertEqual(previous.type, 'request')
        self.assertLess(previous.end_time, result.start_time)
        self.assertEqual(result.data['termination'], 'stop')
        self.assertEqual(result.type, 'response')

    def test_buffer_limit_and_recovery(self):
        hla = Hla()
        hla.MAX_BYTES = 8
        result, = feed(hla, message(payload=list(range(10))))
        self.assertEqual(result.type, 'warning')
        self.assertIn('buffer limit exceeded', result.data['warnings'])
        result, = feed(hla, message(), start=30)
        self.assertEqual(result.type, 'request')

    def test_orphan_data_is_ignored(self):
        hla = Hla()
        self.assertIsNone(hla.decode(Frame('data', 0, 1, {'data': b'\x01', 'ack': True})))
        self.assertIsNone(hla.decode(Frame('stop', 1, 2)))

    def test_final_unterminated_transaction_is_not_claimed_complete(self):
        self.assertEqual(feed(Hla(), message(), stop=False), [])

    def test_manifest(self):
        manifest = json.loads((EXTENSION / 'extension.json').read_text())
        self.assertEqual(manifest['extensions']['IPMI / IPMB']['entryPoint'],
                         'HighLevelAnalyzer.Hla')


if __name__ == '__main__':
    unittest.main()
