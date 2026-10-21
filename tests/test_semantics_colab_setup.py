"""Regression checks for the Colab ensurepip failure and incomplete folders."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import venv

SOURCE = Path(__file__).resolve().parents[1] / "scripts/bootstrap_semantics_colab.py"
spec = importlib.util.spec_from_file_location("semantics_bootstrap", SOURCE)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class ColabSetupTests(unittest.TestCase):
    def test_default_setup_fails_when_ensurepip_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(venv.EnvBuilder, "_setup_pip", side_effect=RuntimeError("ensurepip blocked")):
                with self.assertRaisesRegex(RuntimeError, "ensurepip blocked"):
                    venv.EnvBuilder(with_pip=True).create(Path(directory) / "default")

    def test_new_setup_works_with_ensurepip_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "new"
            with patch.object(venv.EnvBuilder, "_setup_pip", side_effect=RuntimeError("ensurepip blocked")) as blocked:
                python = bootstrap.create_environment(destination)
            blocked.assert_not_called()
            result = json.loads(subprocess.check_output([str(python), "-I", "-c",
                "import sys,json,importlib.util;print(json.dumps([sys.prefix,sys.base_prefix,importlib.util.find_spec('pip') is None]))"], text=True))
            self.assertEqual(Path(result[0]), destination)
            self.assertNotEqual(result[0], result[1])
            self.assertTrue(result[2])

    def test_existing_partial_environment_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "previous-result.txt"
            marker.write_text("preserve")
            with self.assertRaises(FileExistsError):
                bootstrap.create_environment(directory)
            self.assertEqual(marker.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
