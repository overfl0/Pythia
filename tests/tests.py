import os
import platform
import shutil
import subprocess
import unittest


class Base(unittest.TestCase):
    this_dir = os.path.dirname(__file__)

    @property
    def pythia_tester(self):
        name = 'PythiaTester'

        if platform.architecture()[0] == '64bit':
            name += '_x64'

        if platform.system() == 'Windows':
            name += '.exe'

        return name

    def _call_tester(self, *args):
        cmd = os.path.abspath(os.path.join(self.this_dir, self.pythia_tester)), *args
        process = subprocess.run(cmd, capture_output=True, timeout=10, text=True, cwd=self.this_dir)

        return process.stdout, process.stderr, process.returncode

    def setUp(self):
        try:
            os.remove(os.path.join(self.this_dir, self.pythia_tester))
        except FileNotFoundError:
            pass

        tester_path = os.path.join(self.this_dir, '..', '@Pythia', self.pythia_tester)
        shutil.copy2(tester_path, self.this_dir)

    def tearDown(self):
        try:
            os.remove(os.path.join(self.this_dir, self.pythia_tester))
        except FileNotFoundError:
            pass


class TestPythia(Base):
    pythia_path = os.path.join('..', '@Pythia')

    def test_sanity_cant_open_with_local_dir(self):
        output, err, code = self._call_tester('.', 'asd')
        self.assertNotEqual(code, 0, 'Calling the tester with the wrong path should fail')
        self.assertIn('Could not open', output)

    def test_sanity_can_open_with_pythia_dir(self):
        output, err, code = self._call_tester(self.pythia_path, 'asd')
        self.assertEqual(code, 0, 'Calling the tester with the right path succeed')
        self.assertEqual(output, '["r",[1,2,3,4,5,6,7,8,9,0]]')


if __name__ == '__main__':
    unittest.main()
