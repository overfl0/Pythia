import os


def get_sha1_from_file(base_dir, relative_path):
    """
    Try to read base_dir/relative_path. For git head, relative_path should be 'HEAD'.
    If it contains a sha1, return it.
    If it contains a ref, open base_dir/<ref> and return its contents.
    On error, return None
    """
    try:
        head_file_path = os.path.join(base_dir, relative_path)
        head_file = open(head_file_path, "r")
        head_contents = head_file.readlines()

        line = head_contents[0].rstrip('\n')
        if line.startswith('ref: '):
            ref = line[5:]  # Skip the 'ref: '

            ref_file_path = os.path.join(base_dir, ref)
            ref_file = open(ref_file_path, "r")

            ref_file_contents = ref_file.readlines()
            sha1 = ref_file_contents[0].rstrip('\n')
        else:
            sha1 = line
    except (IOError, IndexError) as e:
        sha1 = None

    return sha1


def get_sha1_from_git_directory(base_repo_dir):
    """Get the sha1 of the last commit of a repository.
    The base_repo_dir should contain a direct '.git' subdirectory"""
    return get_sha1_from_file(os.path.join(base_repo_dir, '.git'), 'HEAD')
