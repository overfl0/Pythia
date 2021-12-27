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

    def ensure_no_tester(self):
        try:
            os.remove(os.path.join(self.this_dir, self.pythia_tester))
        except FileNotFoundError:
            pass

    def setUp(self):
        self.maxDiff = 3000
        self.ensure_no_tester()

        tester_path = os.path.join(self.this_dir, '..', '@Pythia', self.pythia_tester)
        shutil.copy2(tester_path, self.this_dir)

    def tearDown(self):
        self.ensure_no_tester()


class TestBasicPing(Base):
    def test_sanity_cant_open_with_local_dir(self):
        request = self.create_request('pythia.ping', [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
        output, err, code = self._call_tester('.', request)
        self.assertNotEqual(code, 0, 'Calling the tester with the wrong path should fail')
        self.assertIn('Could not open', output)

    def test_sanity_can_open_with_pythia_dir(self):
        request = self.create_request('pythia.ping', [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
        output, err, code = self._call_tester(self.pythia_path, request)
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        self.assertEqual(output, '["r",[1,2,3,4,5,6,7,8,9,0]]')


class TestMods(Base):
    def test_basic_loaded_mod(self):
        request = self.create_request('basic.function', [1, 2, 3])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@BasicMod', 'addons', 'basic_mod.pbo')])
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        self.assertEqual(output, '["r",[1,2,3]]')

    def test_renamed_loaded_mod(self):
        request = self.create_request('renamed.function', [1, 2, 3, 4])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@RenamedMod', 'addons', 'renamed_mod.pbo')])
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        self.assertEqual(output, '["r",[1,2,3,4]]')

    def test_special_chars_loaded_mod(self):
        request = self.create_request('zolw.function', [1, 2, 3, 4, 5])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@ŻółwMod', 'addons', 'żółw_mod.pbo')])
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        self.assertEqual(output, '["r",[1,2,3,4,5]]')


class TestSpecialCharsPythia(Base):
    special_chars_pythia_path = '@ŻółwPythia'

    def delete_link(self):
        try:
            os.remove(os.path.abspath(os.path.join(self.this_dir, self.special_chars_pythia_path)))
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            pass

        # Linux symlink + Windows junction
        try:
            os.rmdir(os.path.abspath(os.path.join(self.this_dir, self.special_chars_pythia_path)))
        except FileNotFoundError:
            pass

    def make_link(self, existing_directory, new_name):
        if platform.system() == 'Windows':
            cmd = ['cmd', '/c', 'mklink', '/J', new_name, existing_directory]
            subprocess.run(cmd, check=True, cwd=self.this_dir)
        else:  # Linux
            os.symlink(existing_directory, new_name)

    def setUp(self):
        super().setUp()
        self.delete_link()
        self.make_link(os.path.join(self.this_dir, self.pythia_path),
                       os.path.abspath(os.path.join(self.this_dir, self.special_chars_pythia_path)))

    def tearDown(self):
        super().tearDown()
        self.delete_link()

    def test_pythia_in_directory_with_special_chars(self):
        request = self.create_request('basic.function', [1, 2])
        output, err, code = self._call_tester(self.special_chars_pythia_path, request,
                                              loaded_pbos=[os.path.join('@BasicMod', 'addons', 'basic_mod.pbo')])
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        self.assertEqual(output, '["r",[1,2]]')


if __name__ == '__main__':
    unittest.main()
