#!/usr/bin/env python3

import json
import pathlib
import tempfile
import unittest

import dfc_converter


ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "traces" / "desfire"


class DfcConverterTest(unittest.TestCase):
    def test_credentials_round_trip(self):
        for name in ("H10301-FC69-CN420-factory", "H10301-FC69-CN420-field"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                source = FIXTURES / f"{name}.dfc"
                first_json = pathlib.Path(directory) / "first.json"
                second_dfc = pathlib.Path(directory) / "second.dfc"
                second_json = pathlib.Path(directory) / "second.json"
                dfc_converter.convert(source, first_json)
                dfc_converter.convert(first_json, second_dfc)
                dfc_converter.convert(second_dfc, second_json)
                self.assertEqual(
                    json.loads(first_json.read_text()),
                    json.loads(second_json.read_text()),
                )

    def test_rejects_direction_without_known_extensions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "credential.txt"
            path.write_text("not a credential")
            with self.assertRaisesRegex(dfc_converter.ConversionError, "must be"):
                dfc_converter.convert(path, path.with_suffix(".json"))


if __name__ == "__main__":
    unittest.main()
