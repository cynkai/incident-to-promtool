import unittest

from incident_to_promtool import collect_series


def matrix(timestamp, value):
    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [{"metric": {"__name__": "requests_total"}, "values": [[timestamp, value]]}],
        },
    }


class CaptureMergeTests(unittest.TestCase):
    def test_equal_numeric_values_from_overlapping_selectors_are_deduplicated(self):
        records, shift = collect_series([matrix(31, "1"), matrix(31, "1.0")], 1000, 61000, 30000, False)

        self.assertEqual(records, [{"series": "requests_total", "values": "_ 1"}])
        self.assertEqual(shift, 0)

    def test_disagreement_at_same_timestamp_is_reported(self):
        with self.assertRaisesRegex(ValueError, "conflicting values for requests_total"):
            collect_series([matrix(31, "1"), matrix(31, "2")], 1000, 61000, 30000, False)

    def test_round_up_still_rejects_distinct_timestamps_in_one_slot(self):
        with self.assertRaisesRegex(ValueError, "multiple samples land in one fixture slot"):
            collect_series([matrix(30, "1"), matrix(31, "1.0")], 1000, 61000, 30000, True)
