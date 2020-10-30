#!/usr/bin/env python3

import unittest, sys, findbits

class TestFindBits(unittest.TestCase):
    def setUp(self):
        self.old_stdout = sys.stdout
        sys.stdout = OutputBuffer()

    def tearDown(self):
        sys.stdout = self.old_stdout

    INVERT_CASES = [
            ('10', '01'),
            ('', ''),
            ]
    def test_invert(self):
        self.commutative_test(findbits.invert, self.INVERT_CASES)

    SEARCH_CASES = [
            ('1111', '10111101', ['Match at bit 2', '0<1111>0']),
            ('00', '10111101', ['Not found']),
            ]
    def test_search(self):
        for target, data, expected_fragments in self.SEARCH_CASES:
            sys.stdout.clear_buffer()
            findbits.search(target, data)
            for fragment in expected_fragments:
                self.assertIn(fragment, sys.stdout.content)

    BINSTRING_CASES = [
            (42, '101010'),
            (1, '1'),
            (0, ''),
            ]
    def test_binstring(self):
        self.unary_operation_test(findbits.binstring, self.BINSTRING_CASES)

    REVERSE_CASES = [
            ('abc', 'cba'),
            ('', ''),
            ]
    def test_stringreverse(self):
        self.commutative_test(findbits.stringreverse, self.REVERSE_CASES)

    def commutative_test(self, operation, cases):
        self.unary_operation_test(operation, cases)
        self.unary_operation_test(operation, map(reversed, cases))

    def unary_operation_test(self, operation, cases):
        for case_in, case_out in cases:
            self.assertEqual(operation(case_in), case_out)


class OutputBuffer(object):
    def __init__(self):
        self.clear_buffer()

    def clear_buffer(self):
        self.content = ''

    def write(self, data):
        self.content += data


if __name__ == '__main__':
    unittest.main()
