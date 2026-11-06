"""Payload layouts, safe fallback and configurable HLA output."""

import random
import unittest

from test_hla import Hla, decode_message, feed, message
from payloads import DECODERS, decode_payload


def decode(netfn, command, data=(), request=None, **kwargs):
    return decode_payload(decode_message(message(netfn, command, data, **kwargs)), request)


class PayloadTests(unittest.TestCase):
    def test_synthetic_device_id(self):
        # Invented identity, not a device dump: FW 3.07, IPMI 2.0, product 0xabcd.
        data = bytes.fromhex('42 81 03 07 02 09 00 00 00 cd ab')
        result = decode(7, 1, data)
        self.assertEqual(result['status'], 'decoded')
        self.assertEqual(result['fields']['firmware'], '3.07')
        self.assertEqual(result['fields']['ipmi_version'], '2.0')
        self.assertEqual(result['fields']['manufacturer_id'], 0)
        self.assertEqual(result['fields']['product_id'], 0xABCD)
        self.assertTrue(result['fields']['provides_device_sdr'])
        self.assertIn('FW 3.07', result['summary'])

    def test_device_id_optional_aux_and_invalid_bcd(self):
        data = bytes.fromhex('00 80 82 fa 02 00 01 02 03 04 05 01 02 03 04')
        result = decode(7, 1, data)
        self.assertEqual(result['fields']['auxiliary_firmware_revision'], '01 02 03 04')
        self.assertFalse(result['fields']['device_available'])
        self.assertIn('invalid BCD', result['fields']['firmware'])
        self.assertEqual(decode(7, 1, data[:-1])['status'], 'malformed')

    def test_fru_info_offset_count_and_write(self):
        result = decode(0x0B, 0x10, [0, 2, 1])
        self.assertEqual(result['fields']['inventory_size_bytes'], 512)
        self.assertEqual(result['fields']['access_mode'], 'words')
        result = decode(0x0A, 0x11, [2, 0x34, 0x12, 8])
        self.assertEqual(result['fields'], {'fru_id': 2, 'offset': 0x1234, 'requested_count': 8})
        self.assertIn('access units', result['notes'])
        self.assertEqual(decode(0x0B, 0x11, [2, 0xAA, 0xBB])['fields']['fru_data'], 'aa bb')
        self.assertEqual(decode(0x0B, 0x11, [3, 0xAA, 0xBB])['status'], 'malformed')
        self.assertIn('write=2 bytes', decode(0x0A, 0x12, [0, 0, 0, 1, 2])['summary'])
        self.assertEqual(decode(0x0B, 0x12, [2])['fields']['written_count'], 2)

    def test_sdr_fragment_and_reservation(self):
        for netfn, command in [(4, 0x21), (0x0A, 0x23)]:
            result = decode(netfn, command, [1, 2, 0x34, 0x12, 5, 0xFF])
            self.assertEqual(result['fields']['reservation_id'], 0x0201)
            self.assertEqual(result['fields']['record_id'], 0x1234)
            self.assertIn('count=all', result['summary'])
            result = decode(netfn | 1, command, [0xFF, 0xFF, 0x48, 0x69])
            self.assertEqual(result['fields']['record_data'], '48 69')
            self.assertIn('fragment=2 bytes', result['summary'])
            self.assertNotIn('sensor_name', result['fields'])
        self.assertEqual(decode(5, 0x22, [3, 0])['fields']['reservation_id'], 3)

    def test_device_sdr_selector_needs_valid_request(self):
        self.assertEqual(decode(5, 0x20, [2, 1])['fields']['count_kind'], 'count')
        for data, kind in [([], 'sensors'), ([0], 'sensors'), ([1], 'SDRs')]:
            request = decode_message(message(4, 0x20, data))
            result = decode(5, 0x20, [2, 1], request=request)
            self.assertEqual(result['fields']['count_kind'], kind)
        request = decode_message(message(4, 0x20, [1, 2]))
        self.assertEqual(decode(5, 0x20, [2, 1], request=request)['fields']['count_kind'], 'count')
        self.assertEqual(decode(5, 0x20, [2, 0x80])['status'], 'malformed')
        result = decode(5, 0x20, [2, 0x80, 1, 2, 3, 4])
        self.assertEqual(result['fields']['population_change_indicator'], 0x04030201)

    def test_sensor_reading_no_unjustified_units(self):
        self.assertEqual(decode(4, 0x2D, [42])['fields']['sensor_number'], 42)
        result = decode(5, 0x2D, [0x80, 0xC0, 1, 2])
        self.assertTrue(result['fields']['events_enabled'])
        self.assertTrue(result['fields']['scanning_enabled'])
        self.assertTrue(result['fields']['reading_available'])
        self.assertEqual(result['fields']['reading_raw'], 128)
        self.assertIn('unscaled', result['summary'])
        self.assertEqual(result['fields']['state_bytes'], '01 02')
        self.assertNotIn('voltage', result['fields'])
        result = decode(5, 0x2D, [0x80, 0x20])
        self.assertFalse(result['fields']['reading_available'])
        self.assertEqual(result['summary'], 'reading unavailable')

    def test_event_receiver_and_event(self):
        result = decode(4, 0, [0xFF, 0])
        self.assertIn('events disabled', result['summary'])
        self.assertTrue(result['fields']['event_generation_disabled'])
        self.assertNotIn('events disabled', decode(4, 0, [0, 0])['summary'])
        self.assertEqual(decode(5, 1, [0x20, 2])['fields']['event_receiver_lun'], 2)
        result = decode(4, 2, [4, 1, 37, 1, 4, 5, 6])
        self.assertEqual(result['fields']['sensor_number'], 37)
        self.assertEqual(result['fields']['event_direction'], 'assertion')
        self.assertEqual(result['fields']['event_type'], 1)
        self.assertEqual(result['fields']['event_data'], '04 05 06')
        self.assertNotIn('hot_swap_state', result['fields'])

    def test_picmg_group_guard_and_properties(self):
        result = decode(0x2D, 0, [0, 0x02, 2, 1])
        self.assertEqual(result['fields']['picmg_version'], '2.0')
        self.assertEqual(result['fields']['fru_id'], 1)
        result = decode(0x2D, 0, [0xDC, 0x14, 2, 1])
        self.assertEqual(result['status'], 'raw')
        self.assertEqual(result['fields'], {})

    def test_picmg_leds(self):
        result = decode(0x2C, 7, [0, 0, 0, 0xFF, 0, 1])
        self.assertEqual(result['fields']['led_mode'], 'on')
        self.assertEqual(result['fields']['led_color'], 'blue')
        self.assertIn('FRU=0; LED=0; blue on', result['summary'])
        result = decode(0x2C, 7, [0, 0, 0, 10, 20, 2])
        self.assertEqual(result['fields']['led_off_duration_ms'], 100)
        self.assertEqual(result['fields']['led_on_duration_ms'], 200)
        result = decode(0x2D, 5, [0, 1, 3])
        self.assertEqual(result['fields']['application_led_count'], 3)
        result = decode(0x2D, 6, [0, 2, 1, 1])
        self.assertEqual(result['fields']['supported_colors'], 'blue')
        result = decode(0x2D, 8, [0, 3, 0, 0, 1, 0xFF, 0, 1])
        self.assertTrue(result['fields']['override_active'])
        self.assertEqual(result['fields']['override_mode'], 'on')
        self.assertEqual(decode(0x2D, 8, [0, 2, 0, 0, 1])['status'], 'malformed')

    def test_picmg_activation_and_control(self):
        result = decode(0x2C, 0x0C, [0, 2, 1])
        self.assertEqual(result['fields']['activation_action'], 'activate')
        self.assertEqual(decode(0x2C, 4, [0, 2, 4])['fields']['control_name'], 'quiesce')
        result = decode(0x2C, 0x0A, [0, 2, 3, 1])
        self.assertEqual(result['fields']['policy_mask'], 3)
        result = decode(0x2D, 0x0B, [0, 3])
        self.assertTrue(result['fields']['activation_locked'])
        self.assertTrue(result['fields']['deactivation_locked'])
        self.assertEqual(decode(0x2D, 0x0D, [0, 1, 2])['fields']['record_id'], 0x0201)

    def test_error_and_corrupt_payload_never_decoded_as_success(self):
        result = decode(7, 1, [1, 2, 3], completion=0xC0)
        self.assertEqual(result['status'], 'response_error')
        self.assertEqual(result['fields'], {})
        raw = message(7, 1, [0] * 11)
        raw[-1] ^= 1
        result = decode_payload(decode_message(raw))
        self.assertEqual(result['status'], 'untrusted')
        result = decode_payload(decode_message(message(7, 1, [0] * 11)), trusted=False)
        self.assertEqual(result['fields'], {})

    def test_unknown_short_and_extra_data(self):
        self.assertEqual(decode(6, 0xFE, [1])['status'], 'raw')
        self.assertEqual(decode(7, 1, [1])['status'], 'malformed')
        result = decode(6, 1, [0xFF])  # Get Device ID takes no request data.
        self.assertEqual(result['status'], 'partial')
        self.assertIn('ff', result['notes'])

    def test_all_decoders_tolerate_payload_lengths(self):
        rng = random.Random(42)
        for (netfn, command) in DECODERS:
            for response in (0, 1):
                for count in range(35):
                    data = [rng.randrange(256) for _ in range(count)]
                    if netfn == 0x2C:
                        data = [0] + data
                    with self.subTest(netfn=netfn, command=command, response=response, count=count):
                        result = decode(netfn | response, command, data)
                        self.assertIn(result['status'], ('decoded', 'partial', 'malformed'))
                        self.assertTrue(all(isinstance(v, (str, int, bool))
                                            for v in result['fields'].values()))


class InspectorTests(unittest.TestCase):
    def test_default_labels_and_inspector(self):
        result, = feed(Hla(), message(0x0A, 0x11, [0, 16, 0, 8]))
        self.assertEqual(result.data['label'], 'Read FRU Data [REQ]')
        self.assertIn('offset=16', result.data['decoded'])
        self.assertEqual(result.data['field_offset'], 16)
        self.assertEqual(result.data['payload_status'], 'decoded')

    def test_summary_and_hex_modes(self):
        hla = Hla()
        hla.payload_view = 'Decoded summary'
        result, = feed(hla, message(0x0A, 0x11, [0, 16, 0, 8]))
        self.assertIn('| FRU=0; offset=16; count=8', result.data['label'])
        hla.payload_view = 'Hex bytes'
        result, = feed(hla, message(0x0A, 0x11, [0, 16, 0, 8]), start=10)
        self.assertIn('| data: 00 10 00 08', result.data['label'])

    def test_unknown_fallback_and_preview_limit(self):
        hla = Hla()
        hla.payload_view = 'Decoded summary'
        data = list(range(100))
        result, = feed(hla, message(6, 0xFE, data))
        self.assertIn('| data:', result.data['label'])
        self.assertTrue(result.data['label'].endswith('...'))
        self.assertEqual(result.data['payload'], bytes(data).hex(' '))

    def test_invalid_payload_and_nack_suppress_interpretation(self):
        hla = Hla()
        hla.payload_view = 'Decoded summary'
        result, = feed(hla, message(7, 1, [1]))
        self.assertIn('INVALID PAYLOAD', result.data['label'])
        raw = message(4, 0x2D, [1])
        result, = feed(hla, raw, acks=[True] * (len(raw) - 1) + [False], start=10)
        self.assertEqual(result.data['payload_status'], 'untrusted')
        self.assertNotIn('field_sensor_number', result.data)

    def test_response_request_context(self):
        hla = Hla()
        hla.payload_view = 'Decoded summary'
        feed(hla, message(4, 0x2D, [42]), start=0)
        result, = feed(hla, message(5, 0x2D, [0x80, 0xC0],
                                  destination=0x20, source=0x40), start=1)
        self.assertEqual(result.data['request_match'], 'matched')
        self.assertEqual(result.data['field_request_sensor_number'], 42)
        self.assertIn('sensor=42; raw=0x80', result.data['label'])
        self.assertEqual(result.data['response_latency_ms'], 1000)

    def test_no_request_no_sensor_inference(self):
        result, = feed(Hla(), message(5, 0x2D, [0x80, 0xC0]))
        self.assertEqual(result.data['request_match'], 'unmatched')
        self.assertNotIn('field_request_sensor_number', result.data)

    def test_no_match_with_wrong_address_sequence_lun_or_age(self):
        for changes in ({'sequence': 2}, {'source': 0x42}, {'source_lun': 1}, {'destination_lun': 1}):
            hla = Hla()
            feed(hla, message(4, 0x2D, [42]))
            options = {'destination': 0x20, 'source': 0x40}
            options.update(changes)
            result, = feed(hla, message(5, 0x2D, [1, 0xC0], **options), start=1)
            self.assertEqual(result.data['request_match'], 'unmatched')
        hla = Hla()
        feed(hla, message(4, 0x2D, [42]))
        result, = feed(hla, message(5, 0x2D, [1, 0xC0], destination=0x20, source=0x40), start=6)
        self.assertEqual(result.data['request_match'], 'unmatched')

    def test_interleaved_multimaster_requests_and_retries(self):
        hla = Hla()
        feed(hla, message(4, 0x2D, [1], source=0x20))
        feed(hla, message(4, 0x2D, [2], source=0x22), start=1)
        feed(hla, message(4, 0x2D, [1], source=0x20), start=2)
        for destination, sensor, start in [(0x22, 2, 3), (0x20, 1, 4)]:
            result, = feed(hla, message(5, 0x2D, [7, 0xC0], destination=destination, source=0x40), start=start)
            self.assertEqual(result.data['field_request_sensor_number'], sensor)

    def test_ambiguous_sequence_reuse_is_not_guessed(self):
        hla = Hla()
        feed(hla, message(4, 0x2D, [1]))
        feed(hla, message(4, 0x2D, [2]), start=1)
        result, = feed(hla, message(5, 0x2D, [7, 0xC0], destination=0x20, source=0x40), start=2)
        self.assertEqual(result.data['request_match'], 'ambiguous')
        self.assertNotIn('field_request_sensor_number', result.data)

    def test_group_prefix_and_request_cache_bound(self):
        hla = Hla()
        hla.MAX_PENDING = 2
        feed(hla, message(0x2C, 0, [0]))
        result, = feed(hla, message(0x2D, 0, [0xDC, 0x14, 0, 0],
                                  destination=0x20, source=0x40), start=1)
        self.assertEqual(result.data['request_match'], 'unmatched')
        for sequence in range(3):
            feed(hla, message(4, 0x2D, [1], sequence=sequence), start=2)
        self.assertLessEqual(len(hla.pending), 2)

    def test_bad_request_and_separate_instances_do_not_supply_context(self):
        raw = message(4, 0x2D, [42])
        raw[-1] ^= 1
        hla = Hla()
        feed(hla, raw)
        result, = feed(hla, message(5, 0x2D, [1, 0xC0], destination=0x20, source=0x40), start=1)
        self.assertEqual(result.data['request_match'], 'unmatched')
        feed(hla, message(4, 0x2D, [42]), start=2)
        result, = feed(Hla(), message(5, 0x2D, [1, 0xC0], destination=0x20, source=0x40), start=3)
        self.assertNotIn('field_request_sensor_number', result.data)

    def test_lun_swapping_and_time_reversal(self):
        for start, expected in [(1, 'matched'), (-1, 'unmatched')]:
            hla = Hla()
            feed(hla, message(4, 0x2D, [42], source_lun=1, destination_lun=2))
            result, = feed(hla, message(5, 0x2D, [1, 0xC0], destination=0x20, source=0x40,
                                      source_lun=2, destination_lun=1), start=start)
            self.assertEqual(result.data['request_match'], expected)

    def test_group_only_success_does_not_add_fake_application_data(self):
        hla = Hla()
        hla.payload_view = 'Decoded summary'
        result, = feed(hla, message(0x2C, 0, [0]))
        self.assertEqual(result.data['label'], 'Get PICMG Properties [REQ]')


if __name__ == '__main__':
    unittest.main()
