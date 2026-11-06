#!/usr/bin/env python3
"""
Test Suite Runner & Quality Assurance Dashboard for CyberMemory AI.
Executes all unit, security, integration, and comparative benchmark test cases.
"""

import sys
import os
import unittest
import time

# Ensure project root is in path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)


def main():
    print("=" * 70)
    print("  CYBERMEMORY AI — AUTOMATED TEST SUITE & SECURITY AUDIT")
    print("  Branch: feature/data-testing | Role: Data, Security & Testing")
    print("=" * 70)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(ROOT_DIR, "tests"), pattern="test_*.py")

    start_time = time.time()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    duration = time.time() - start_time

    print("\n" + "=" * 70)
    print("  TEST EXECUTION SUMMARY")
    print("=" * 70)
    print(f"  Total Tests Run: {result.testsRun}")
    print(f"  Successes:      {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"  Failures:       {len(result.failures)}")
    print(f"  Errors:         {len(result.errors)}")
    print(f"  Total Duration: {duration:.3f} seconds")
    print("=" * 70)

    if result.wasSuccessful():
        print("  >>> ALL TEST CASES PASSED WITH 100% SUCCESS <<<")
        sys.exit(0)
    else:
        print("  >>> DEFECTS DETECTED IN TEST RUN <<<")
        sys.exit(1)


if __name__ == "__main__":
    main()

