import os
import platform
import shutil
import subprocess
import unittest


class Base(unittest.TestCase):
    this_dir = os.path.abspath(os.path.dirname(__file__))
    pythia_path = os.path.join('..', '@Pythia')

    @property
    def pythia_tester(self):
        name = 'PythiaTester'

        if platform.architecture()[0] == '64bit':
            name += '_x64'

        if platform.system() == 'Windows':
            name += '.exe'

        return name

    def _call_tester(self, *args, loaded_pbos=None):
        if not loaded_pbos:
            loaded_pbos = []

        cmd = [os.path.abspath(os.path.join(self.this_dir, self.pythia_tester))]

        for pbo in loaded_pbos:
            cmd.extend(['-o', pbo])

        cmd += args
        process = subprocess.run(cmd, capture_output=True, timeout=10, text=True, cwd=self.this_dir)

        return process.stdout, process.stderr, process.returncode

    @staticmethod
    def create_request(function, args):
        return f'["{function}", {args}]'

    def setUp(self):
        self.maxDiff = 3000
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


class TestBasicPing(Base):
    def test_sanity_cant_open_with_local_dir(self):
        request = self.create_request('pythia.ping', [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
        output, err, code = self._call_tester('.', request)
        self.assertNotEqual(code, 0, 'Calling the tester with the wrong path should fail')
        self.assertIn('Could not open', output)

    def test_sanity_can_open_with_pythia_dir(self):
        request = self.create_request('pythia.ping', [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
        output, err, code = self._call_tester(self.pythia_path, request)
        self.assertEqual(code, 0, 'Calling the tester with the right path succeed')
        self.assertEqual(output, '["r",[1,2,3,4,5,6,7,8,9,0]]')


class TestMods(Base):
    def test_basic_loaded_mod(self):
        request = self.create_request('basic.function', [1, 2, 3])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@BasicMod', 'addons', 'basic_mod.pbo')])
        self.assertEqual(code, 0, 'Calling the tester with the right path succeed')
        self.assertEqual(output, '["r",[1,2,3]]')

    def test_renamed_loaded_mod(self):
        request = self.create_request('renamed.function', [1, 2, 3, 4])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@RenamedMod', 'addons', 'renamed_mod.pbo')])
        self.assertEqual(code, 0, 'Calling the tester with the right path succeed')
        self.assertEqual(output, '["r",[1,2,3,4]]')


if __name__ == '__main__':
    unittest.main()
