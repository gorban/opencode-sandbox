"""Exercise the disposable SonarCloud coverage fixture."""

import unittest

from docs.prds.spikes.k.coverage_fixture import covered, remaining


class CoverageFixtureTest(unittest.TestCase):
    def test_covered_sum(self):
        self.assertEqual(covered(), 300)

    def test_remaining_line(self):
        self.assertEqual(remaining(), 100)
