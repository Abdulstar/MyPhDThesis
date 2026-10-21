"""Check that pairing does not turn repeated seeds or clean misses into samples."""
import unittest

import numpy as np

from scripts.summarize_frozen_followup import paired_effect


class PairedFollowupTests(unittest.TestCase):
    def test_seeds_are_averaged_within_each_original(self):
        end = np.zeros((3, 3), dtype=bool)
        loop = np.array([[True, True, True], [True, False, False], [False, False, False]])
        difference, result = paired_effect(end, loop, np.array([True, True, False]))
        np.testing.assert_allclose(difference, [1, 1/3, 0])
        self.assertEqual(result["detected_originals"], 2)
        self.assertAlmostEqual(result["mean_difference_pp"], 200/3)
        self.assertEqual(result["originals_favoring_inloop"], 2)

    def test_improvements_and_regressions_are_both_retained(self):
        end = np.array([[False, False, False], [True, True, True]])
        loop = ~end
        _, result = paired_effect(end, loop, np.ones(2, dtype=bool))
        self.assertEqual(result["mean_difference_pp"], 0)
        self.assertEqual(result["originals_favoring_inloop"], 1)
        self.assertEqual(result["originals_favoring_end"], 1)
        self.assertEqual(result["exploratory_95pct_interval_pp"], [-100, 100])

    def test_existing_clean_miss_cannot_be_a_new_evasion(self):
        with self.assertRaisesRegex(ValueError, "Clean misses"):
            paired_effect(np.zeros((1, 3), bool), np.ones((1, 3), bool), np.zeros(1, bool))

    def test_zero_detection_denominator_is_undefined(self):
        _, result = paired_effect(np.zeros((2, 3), bool), np.zeros((2, 3), bool), np.zeros(2, bool))
        self.assertIsNone(result["mean_difference_pp"])
        self.assertIsNone(result["exploratory_95pct_interval_pp"])

    def test_repeated_seeds_do_not_create_three_times_the_sample(self):
        _, result = paired_effect(np.zeros((4, 3), bool), np.ones((4, 3), bool), np.ones(4, bool))
        self.assertEqual(result["detected_originals"], 4)
        self.assertEqual(result["mean_difference_pp"], 100)
        self.assertTrue(result["degenerate_empirical_interval"])


if __name__ == "__main__":
    unittest.main()
