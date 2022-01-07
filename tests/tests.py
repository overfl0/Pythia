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

    def _call_tester(self, *args, loaded_pbos=None, timeout=10):
        if not loaded_pbos:
            loaded_pbos = []

        cmd = [os.path.abspath(os.path.join(self.this_dir, self.pythia_tester))]

        for pbo in loaded_pbos:
            cmd.extend(['-o', pbo])

        cmd += args
        process = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True, cwd=self.this_dir)

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
        try:
            self.assertNotEqual(code, 0, 'Calling the tester with the wrong path should fail')
        except AssertionError:
            print(output)
            raise
        self.assertIn('Could not open', output)

    def test_sanity_can_open_with_pythia_dir(self):
        request = self.create_request('pythia.ping', [1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
        output, err, code = self._call_tester(self.pythia_path, request)
        try:
            self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        except AssertionError:
            print(output)
            raise
        self.assertEqual(output, '["r",[1,2,3,4,5,6,7,8,9,0]]')


class TestMods(Base):
    def test_basic_loaded_mod(self):
        request = self.create_request('basic.function', [1, 2, 3])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@BasicMod', 'addons', 'basic_mod.pbo')])
        try:
            self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        except AssertionError:
            print(output)
            raise
        self.assertEqual(output, '["r",[1,2,3]]')

    def test_renamed_loaded_mod(self):
        request = self.create_request('renamed.function', [1, 2, 3, 4])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@RenamedMod', 'addons', 'renamed_mod.pbo')])
        try:
            self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        except AssertionError:
            print(output)
            raise
        self.assertEqual(output, '["r",[1,2,3,4]]')

    def test_special_chars_loaded_mod(self):
        request = self.create_request('zolw.function', [1, 2, 3, 4, 5])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@ŻółwMod', 'addons', 'żółw_mod.pbo')])
        try:
            self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        except AssertionError:
            print(output)
            raise
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
        try:
            self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        except AssertionError:
            print(output)
            raise
        self.assertEqual(output, '["r",[1,2]]')


class RequirementsInstaller(Base):
    def _install_requirements(self, requirements_file_path):
        requirements_installer_path = os.path.join(self.this_dir, self.pythia_path, 'install_requirements')
        if platform.system() == 'Windows':
            requirements_installer_path += '.bat'
        else:
            requirements_installer_path += '.sh'

        if platform.system() == 'Windows':
            cmd = ['cmd', '/c', requirements_installer_path, 'nopause', requirements_file_path]
        else:
            cmd = ['/bin/bash', requirements_installer_path, requirements_file_path]

        process = subprocess.run(cmd, capture_output=True, timeout=60, text=True, cwd=self.this_dir)

        try:
            self.assertEqual(process.returncode, 0, 'Calling the tester with the right path should succeed')
        except AssertionError:
            print(process.stdout)
            print(process.stderr)
            raise


class TestRequirements(RequirementsInstaller):
    def _uninstall_requests(self):
        request = self.create_request('requirements_mod.uninstall_requests', [])
        output, err, code = self._call_tester(
            self.pythia_path, request, loaded_pbos=[os.path.join('@RequirementsMod', 'addons', 'requirements_mod.pbo')])
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        self.assertTrue(output == '["r",nil]' or 'Successfully uninstalled requests' in output)

    def _check_if_requests_fail(self):
        request = self.create_request('requirements_mod.get_requests_version', [])
        output, err, code = self._call_tester(
            self.pythia_path, request, loaded_pbos=[os.path.join('@RequirementsMod', 'addons', 'requirements_mod.pbo')])
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        self.assertIn('ModuleNotFoundError', output)

    def _check_if_requests_installed(self):
        request = self.create_request('requirements_mod.get_requests_version', [])
        output, err, code = self._call_tester(
            self.pythia_path, request, loaded_pbos=[os.path.join('@RequirementsMod', 'addons', 'requirements_mod.pbo')])

        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        self.assertEqual(output, '["r","2.26.0"]')

    def test_installing_requirements(self):
        requirements_file_path = os.path.join(self.this_dir, '@RequirementsMod', 'requirements.txt')
        self._uninstall_requests()
        self._check_if_requests_fail()
        self._install_requirements(requirements_file_path)
        self._check_if_requests_installed()


class TestCython(RequirementsInstaller):
    def test_cython_mod(self):
        # Install the Cython requirements to build the extension
        requirements_file_path = os.path.join(self.this_dir, '@CythonMod', 'requirements.txt')
        self._install_requirements(requirements_file_path)

        # Note: DON'T do this normally. This is just a workaround to ensure
        # that the right python interpreter is called! You're supposed to have
        # a script that will probably call both pythons in sequence to build
        # the extension for both 32bit and 64bit
        setup_py_path = os.path.join(self.this_dir, '@CythonMod')
        request = self.create_request('cython_basic.compile_python_extension_do_not_use_this_way', [setup_py_path])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@CythonMod', 'addons', 'cython_mod.pbo')],
                                              timeout=30)

        # Mild check
        self.assertIn('running build_ext', output)
        self.assertNotIn('failed', output)
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')

        # Try calling the function
        request = self.create_request('cython_basic.function', [1, 2, 3])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@CythonMod', 'addons', 'cython_mod.pbo')])
        self.assertEqual(output, '["r","Hello from cython!"]')
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')

    def test_cython_numpy_mod(self):
        # Install the Cython requirements to build the extension
        requirements_file_path = os.path.join(self.this_dir, '@CythonNumpyMod', 'requirements.txt')
        self._install_requirements(requirements_file_path)

        # Note: DON'T do this normally. This is just a workaround to ensure
        # that the right python interpreter is called! You're supposed to have
        # a script that will probably call both pythons in sequence to build
        # the extension for both 32bit and 64bit
        setup_py_path = os.path.join(self.this_dir, '@CythonNumpyMod')
        request = self.create_request('cython_numpy_basic.compile_python_extension_do_not_use_this_way',
                                      [setup_py_path])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@CythonNumpyMod', 'addons',
                                                                        'cython_numpy_mod.pbo')],
                                              timeout=120)

        # Mild check
        self.assertIn('running build_ext', output)
        self.assertNotIn('failed', output)
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')

        # Try calling the function
        request = self.create_request('cython_numpy_basic.function', [1, 2, 3, 4])
        output, err, code = self._call_tester(self.pythia_path, request,
                                              loaded_pbos=[os.path.join('@CythonNumpyMod', 'addons',
                                                                        'cython_numpy_mod.pbo')])
        self.assertEqual(output, '["r","Hello from numpy cython!"]')
        self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')


class TestLongDirectory(Base):
    dir_length = 250

    def _delete_directory(self):
        try:
            shutil.rmtree(os.path.join(self.this_dir, '0' * self.dir_length))
        except FileNotFoundError:
            pass

    def setUp(self):
        super().setUp()
        self._delete_directory()

        current_dir = os.getcwd()
        try:
            # Create the directory by chdiring and creating a subdirectory one by one
            # Because it's sometimes a problem to give abspaths... supposedly
            os.chdir(self.this_dir)
            for i in range(10):
                next_dir = str(i) * self.dir_length
                os.mkdir(next_dir)
                os.chdir(next_dir)

            self.long_directory_path = os.getcwd()

            shutil.copytree(os.path.join(self.this_dir, '@BasicMod'),
                            os.path.join(self.long_directory_path, '@BasicMod'))
        finally:
            os.chdir(current_dir)

    def tearDown(self):
        super().tearDown()
        self._delete_directory()

    def test_long_directory(self):
        request = self.create_request('basic.function', [6, 7, 8])
        output, err, code = self._call_tester(
            self.pythia_path,
            request,
            loaded_pbos=[os.path.join(self.long_directory_path, '@BasicMod', 'addons', 'basic_mod.pbo')]
        )
        try:
            self.assertEqual(code, 0, 'Calling the tester with the right path should succeed')
        except AssertionError:
            print(output)
            raise
        self.assertEqual(output, '["r",[6,7,8]]')


if __name__ == '__main__':
    unittest.main()
