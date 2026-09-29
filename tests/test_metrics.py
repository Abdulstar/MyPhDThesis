import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "baseline"))
import numpy as np
from metrics import attack_metrics, clean_metrics, select_malicious


class WorkflowTests(unittest.TestCase):
    def test_attack_selection_is_malicious_and_valid(self):
        y = np.array([0, 1, 0, 1, 1, 0])
        valid = np.array([True, True, True, False, True, True])
        chosen = select_malicious(y, valid, n=0, seed=0)
        np.testing.assert_array_equal(chosen, [1, 4])
        a = select_malicious(y, valid, n=1, seed=0)
        b = select_malicious(y, valid, n=1, seed=0)
        np.testing.assert_array_equal(a, b)
        self.assertTrue((y[a] == 1).all())

    def test_confusion_matrix_denominators(self):
        y = np.array([0, 0, 0, 1, 1])
        proba = np.array([[.9,.1], [.4,.6], [.7,.3], [.1,.9], [.8,.2]])
        out = clean_metrics(y, proba)
        self.assertEqual([out[k] for k in ['tn','fp','fn','tp']], [2,1,1,1])
        self.assertAlmostEqual(out['false_positive_rate'], 1/3)
        self.assertAlmostEqual(out['recall'], .5)
        self.assertAlmostEqual(out['accuracy'], .6)

    def test_invalid_candidates_do_not_count_as_new_evasion(self):
        clean = np.array([1, 1, 0, 1])
        adv = np.array([0, 0, 0, 0])
        valid = np.array([True, False, True, True])
        in_budget = np.array([True, True, True, False])
        out = attack_metrics(clean, adv, valid, in_budget)
        self.assertEqual(out['newly_evaded'], 1)
        self.assertEqual(out['already_missed_before_attack'], 1)
        self.assertAlmostEqual(out['new_evasion_rate_among_initially_detected'], 1/3)
        self.assertAlmostEqual(out['malicious_recall_after_attack'], .5)


if __name__ == '__main__':
    unittest.main()
