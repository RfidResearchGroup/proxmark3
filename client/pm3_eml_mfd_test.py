#!/usr/bin/python

from __future__ import with_statement
from tempfile import mkdtemp
from shutil import rmtree
from itertools import imap
from string import hexdigits
import unittest, os
import pm3_eml2mfd, pm3_mfd2eml

class TestEmlMfd(unittest.TestCase):
    def setUp(self):
        self.tmpdir = mkdtemp()
    
    def tearDown(self):
        rmtree(self.tmpdir)

    EML2MFD_TESTCASES = [
            ('', ''),
            ("41424344\r\n45464748\n494A4B4C\n", "ABCDEFGHIJKL")
            ]
    def test_eml2mfd(self):
        self.three_argument_test(pm3_eml2mfd.main, self.EML2MFD_TESTCASES)
    
    def test_mfd2eml(self):
        self.three_argument_test(pm3_mfd2eml.main,
                imap(reversed, self.EML2MFD_TESTCASES), c14n=hex_c14n)

    def three_argument_test(self, operation, cases, c14n=str):
        for case_input, case_output in cases:
            try:
                inp_name = os.path.join(self.tmpdir, 'input')
                out_name = os.path.join(self.tmpdir, 'output')
                with file(inp_name, 'wb') as in_file:
                    in_file.write(case_input)
                operation(['', inp_name, out_name])
                with file(out_name, 'rb') as out_file:
                    self.assertEquals(c14n(case_output), c14n(out_file.read()))
            finally:
                for file_name in inp_name, out_name:
                    if os.path.exists(file_name):
                        os.remove(file_name)


def hex_c14n(inp):
    """
    Canonicalizes the input string by removing non-hexadecimal
    characters and making everything uppercase
    """ 
    return ''.join(c.upper() for c in inp if c in hexdigits)

if __name__ == '__main__':
    unittest.main()
