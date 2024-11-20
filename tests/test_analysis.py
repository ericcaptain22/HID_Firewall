# File: tests/test_analysis.py

import unittest
from scripts.malicious_input_engine import analyze_keystroke, load_trained_model

class TestMaliciousInputEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Load the model and vectorizer once for all tests
        cls.vectorizer, cls.clf = load_trained_model()

    def test_benign_keystroke(self):
        benign_keystroke = "ls -la"
        self.assertFalse(analyze_keystroke(benign_keystroke, self.vectorizer, self.clf))

    def test_malicious_keystroke(self):
        malicious_keystroke = "rm -rf /"
        self.assertTrue(analyze_keystroke(malicious_keystroke, self.vectorizer, self.clf))

if __name__ == '__main__':
    unittest.main()
