"""Mocked G95NC state transitions. Run: python -m unittest discover -s tests -v"""
import ctypes
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


CONTROLLER = Path(__file__).resolve().parents[1] / 'windows' / 'samsung_pbpctl_win.py'


def load_controller():
    # Allow loading the Win32-only module on development systems without dxva2.
    with patch.object(ctypes, 'windll', create=True), patch.object(ctypes, 'WINFUNCTYPE', ctypes.CFUNCTYPE, create=True):
        import ctypes.wintypes as wt
        with patch.object(wt, 'HMONITOR', ctypes.c_void_p, create=True):
            spec = importlib.util.spec_from_file_location('samsung_pbpctl_win', CONTROLLER)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module


class EnsureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_controller()

    def simulate(self, initial, events, target, timeout=10.0):
        """events are states returned after each write (including stale reads)."""
        current = [initial]
        sequence = []
        writes = []
        clock = [0.0]

        def find(strict=False):
            self.assertTrue(strict)
            return None, 'G95NC test monitor'  # Real hardware can return handle=None.

        def get(_handle, code):
            self.assertEqual(code, 0xE2)
            if sequence:
                current[0] = sequence.pop(0)
            return current[0], 0x7f

        def set_vcp(_handle, code, value):
            self.assertEqual(code, 0xE2)
            writes.append(value)
            sequence.extend(events.get(len(writes), []))
            return True

        def sleep(duration):
            clock[0] += duration

        with patch.object(self.mod, 'find_g95nc', side_effect=find), \
             patch.object(self.mod, 'get_vcp', side_effect=get), \
             patch.object(self.mod, 'set_vcp', side_effect=set_vcp), \
             patch.object(self.mod.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(self.mod.time, 'sleep', side_effect=sleep):
            rc = self.mod.ensure_e2(target, timeout)
        return rc, writes

    def test_already_correct_no_write(self):
        self.assertEqual(self.simulate(0x39D3, {}, 0x04), (0, []))

    def test_pbp_to_pbp_polls_stale_state(self):
        self.assertEqual(self.simulate(0x39D3, {1: [0x39D3, 0x39D1]}, 0x03), (0, [0x03]))

    def test_pbp_to_single_dp_variant(self):
        self.assertEqual(self.simulate(0x39D3, {1: [0x39D3, 0x39D2]}, 0x00), (0, [0x00]))

    def test_single_enable_restores_target(self):
        self.assertEqual(self.simulate(0x39D2, {1: [0x39D2, 0x39D3]}, 0x04), (0, [0x01]))

    def test_single_enable_then_layout(self):
        self.assertEqual(self.simulate(0x39D2, {1: [0x39D2, 0x39D1], 2: [0x39D1, 0x39D3]}, 0x04), (0, [0x01, 0x04]))

    def test_unknown_intermediate_does_not_trigger_write(self):
        rc, writes = self.simulate(0x39D2, {1: [0x39D2, 0x39DF]}, 0x04, timeout=2)
        self.assertEqual((rc, writes), (1, [0x01]))

    def test_timeout_does_not_repeat_write(self):
        rc, writes = self.simulate(0x39D3, {1: [0x39D3]}, 0x03, timeout=2)
        self.assertEqual((rc, writes), (1, [0x03]))

    def test_strict_monitor_selection_rejects_fallback(self):
        with patch.object(self.mod, '_physical_monitors', return_value=[(12, 'Other monitor')]), \
             patch.object(self.mod, 'get_vcp', return_value=(0x39D3, 0x7f)):
            self.assertEqual(self.mod.find_g95nc(strict=True), (None, None))
            self.assertEqual(self.mod.find_g95nc(), (12, 'Other monitor'))

    def test_strict_selection_allows_none_handle_when_identified(self):
        with patch.object(self.mod, '_physical_monitors', return_value=[(None, 'G95NC DP PBP')]), \
             patch.object(self.mod, 'get_vcp', return_value=(0x39D3, 0x7f)):
            self.assertEqual(self.mod.find_g95nc(strict=True), (None, 'G95NC DP PBP'))

    def test_unsupported_value_no_write(self):
        with patch.object(self.mod, 'set_vcp') as writer:
            self.assertEqual(self.mod.ensure_e2(0x08), 2)
            writer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
