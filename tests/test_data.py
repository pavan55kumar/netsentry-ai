import unittest
from netsentry.data import make_demo_dataset, prepare_data

class DataTests(unittest.TestCase):
    def test_demo_split_is_binary_and_disjoint(self):
        prepared = prepare_data(make_demo_dataset(rows=100, random_state=7), "label", random_state=7)
        self.assertEqual(set(prepared.y_train.unique()) | set(prepared.y_test.unique()), {0, 1})
        self.assertEqual(len(prepared.feature_names), 8)
        self.assertFalse(set(map(tuple, prepared.X_train.to_numpy())) & set(map(tuple, prepared.X_test.to_numpy())))
if __name__ == "__main__": unittest.main()
