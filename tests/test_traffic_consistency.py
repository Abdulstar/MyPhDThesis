import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "baseline"))
from traffic_consistency import (aggregate_pairs, support_failures, checked_archive,
    unpack_evidence, load_npz, merge_candidate, evasion_options, select_with_final_gate)


class TrafficConsistencyTests(unittest.TestCase):
    def test_rule_covers_incoming_and_outgoing_and_has_no_duration_cap(self):
        protocol = json.loads((Path(__file__).resolve().parents[1] /
                               "baseline/traffic_consistency_protocol.json").read_text())
        names = [m + "_" + a + "_" + d + "_" + p for m in protocol["metrics"]
                 for d in protocol["directions"] for p in protocol["ports"] for a in ("sum", "max")]
        pairs = aggregate_pairs(names, protocol)
        self.assertEqual(len(pairs), 180)
        x = np.zeros((3, len(names)), dtype=np.float32)
        for pair in pairs:
            x[1, pair["sum_index"]] = 2
            x[2, pair["sum_index"]] = 10 ** 9
            x[2, pair["max_index"]] = 10 ** 9
        failed = support_failures(x, pairs)
        self.assertFalse(failed[0].any())  # Empty/missing-zero bucket.
        self.assertTrue(failed[1].all())  # All five families, both endpoint roles.
        self.assertFalse(failed[2].any())  # No invented time-window duration limit.
        np.testing.assert_array_equal(failed, support_failures(x.astype(np.float64), pairs))

    def test_alternative_evasion_survives_and_duplicates_are_not_new_records(self):
        pools = [dict(), dict()]
        for source in ("z", "a"):
            merge_candidate(pools, 0, np.array([2], np.float32), .1, .2, source, 0, False, 0)
        merge_candidate(pools, 0, np.array([3], np.float32), .2, .3, "b", 1, True, 0)
        merge_candidate(pools, 1, np.array([3], np.float32), .2, .3, "b", 1, True, 0)
        self.assertEqual(len(pools[0]), 2)
        native = evasion_options(pools, np.array([1, 0]), False)
        added = evasion_options(pools, np.array([1, 0]), True)
        self.assertEqual(native[0][0]["source"], "a")
        self.assertEqual(added[0][0]["source"], "b")
        self.assertEqual(added[1], [])  # Already missed original is not a new evasion.

    def test_final_matrix_rejection_advances_to_alternative_and_preserves_clean(self):
        clean = np.zeros((2, 1), dtype=np.float32)
        pools = [dict(), dict()]
        for v, score in [(2, .1), (3, .2)]:
            merge_candidate(pools, 0, np.array([v], np.float32), score, .2, "source", v, True, 0)
        options = evasion_options(pools, [1, 1], True)
        def gate(x):
            self.assertEqual(x.shape, (2, 1))
            return x[:, 0] != 2
        x, chosen, rejected = select_with_final_gate(clean, options, gate)
        np.testing.assert_array_equal(x[:, 0], [3, 0])
        np.testing.assert_array_equal(clean, np.zeros_like(clean))
        self.assertEqual(len(rejected), 1)
        self.assertEqual(chosen[0]["index"], 3)
        self.assertIsNone(chosen[1])

    def test_exhausted_options_fall_back_to_clean(self):
        clean = np.zeros((1, 1), dtype=np.float32)
        pools = [dict()]
        merge_candidate(pools, 0, np.array([1], np.float32), .1, .2, "s", 0, True, 0)
        x, chosen, rejected = select_with_final_gate(clean, evasion_options(pools, [1], True),
                                                     lambda x: x[:, 0] == 0)
        np.testing.assert_array_equal(x, clean)
        self.assertEqual(chosen, [None])
        self.assertEqual(len(rejected), 1)
        with self.assertRaisesRegex(ValueError, "clean control"):
            select_with_final_gate(clean, [[]], lambda x: np.array([False]))

    def test_archive_paths_symlinks_size_and_existing_evidence_rejected(self):
        for name, mode in [("../outside", 0), ("/outside", 0), ("a\\b", 0),
                           ("link", stat.S_IFLNK | 0o777)]:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                z.writestr(info, b"target")
            buf.seek(0)
            with self.assertRaises(ValueError):
                checked_archive(buf)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("file", b"1234")
        buf.seek(0)
        with self.assertRaisesRegex(ValueError, "size"):
            checked_archive(buf, max_bytes=3)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileExistsError):
                unpack_evidence("unused.zip", tmp)

    def test_nested_numpy_headers_and_object_arrays_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "arrays.npz"
            np.savez_compressed(path, x=np.zeros((2, 3), dtype=np.float32))
            self.assertEqual(load_npz(path)["x"].shape, (2, 3))
            np.savez_compressed(path, x=np.array([{}], dtype=object))
            with self.assertRaises(ValueError):
                load_npz(path)
            buf = io.BytesIO()
            np.lib.format.write_array_header_1_0(buf, {"descr": "<f4", "fortran_order": False,
                                                       "shape": (1000000000,)})
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("x.npy", buf.getvalue())
            with self.assertRaisesRegex(ValueError, "header"):
                load_npz(path)


if __name__ == "__main__":
    unittest.main()
