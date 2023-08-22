from typing import List, Tuple, TextIO
import os
from tqdm.auto import tqdm
import pickle
import hashlib

from prompting import chagpt_analyze
from description import Vulnerability, File, Directory
import tiktoken

tokenizer = tiktoken.encoding_for_model("gpt-4")

SERVICE_ROOT = '/Users/dmitry/projects/ctf-training/amogus_plus_plus'

from typing import List, Tuple
import os

IGNORE_FILENAMES_LIST = set([
    '.DS_Store',
    'LICENSE',
    'README.md',
    'package-lock.json',
    '.prettierrc',
    '.prettierignore',
])
IGNORE_FILENAMES_PREFIXES = [
    '.git',
    '.idea',
    '.vscode',
    '__pycache__',
    'venv',
]

MAX_TOKENS = 4096

def is_binary_file(filepath: str) -> bool:
    """Check if a file is binary"""
    with open(filepath, 'rb') as file:
        chunk = file.read(1024)
        return b'\0' in chunk

def list_service_directory(service_root: str, debug: bool = False) -> Tuple[List[Directory], List[File], List[File | Directory]]:
    """List all directories and files in the service root directory. Names are relative to service root."""
    directories = []
    files = []
    project_structure = []
    MAX_FILES = 20
    for root, dirs, filenames in os.walk(service_root):
        relative_root = os.path.relpath(root, service_root)
        directory_description = Directory(
            path=relative_root,
            files_count=len(filenames),
            subdirectories_count=len(dirs),
        )
        if directory_description.files_count == 0 and directory_description.subdirectories_count == 0:
            continue

        directories.append(directory_description)
        project_structure.append(directory_description)

        if debug:
            print(directory_description)
        
        directory_file_count = 0
        for filename in filenames:
            filepath = os.path.join(root, filename)
            relative_filepath = os.path.relpath(filepath, service_root)
            extension = os.path.splitext(filename)[1]
            filename = os.path.basename(filename)

            need_skip = False
            is_binary = is_binary_file(filepath)
            lines_count = sum(1 for line in open(filepath, 'r', encoding='utf-8', errors='ignore')) if not is_binary_file(filepath) else 0

            for ignore_prefix in IGNORE_FILENAMES_PREFIXES:
                if filename.startswith(ignore_prefix):
                    need_skip = True
                    break
            if lines_count == 0 or is_binary or need_skip or filename in IGNORE_FILENAMES_LIST:
                continue
            
            file_description = File(
                root=service_root,
                path=relative_filepath, 
                lines_count=lines_count,
                extension=extension, 
                is_binary=is_binary,
            )
            directory_file_count += 1
            if directory_file_count > MAX_FILES:
                break
            files.append(file_description)
            project_structure.append(file_description)
            if debug:
                print(file_description)

    return directories, files, project_structure

def analyze_file(service_root: str, file_description: File, project_structure: List[File | Directory], debug: bool = False) -> List[Tuple[File, Vulnerability]]:
    """Using simple completion to obtain vulnerability analysis"""
    vulnerabilities = []
    if file_description.is_binary:
        return vulnerabilities  # Skip binary files

    print("ANALYZING FILE:")
    print(file_description)

    filepath = os.path.join(service_root, file_description.path)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        code_lines = file.readlines()
        code = '\n'.join(code_lines)

    tokens = tokenizer.encode(code)
    if len(tokens) > MAX_TOKENS:
        print("TOO LONG FILE")
        return vulnerabilities

    vulnerabilities = chagpt_analyze(
        file_description=file_description,
        code=code,
        project_structure=project_structure,
        debug=debug
    )
     
    return vulnerabilities


def analyze_vulnerability(service_root: str, output: TextIO, debug=False) -> List[Tuple[File, Vulnerability]]:
    directories, files, project_structure = list_service_directory(service_root, debug=debug)
    vulnerabilities = []
    
    # Read state file to get already analyzed files
    analyzed_files = []
    # Create a unique identifier for the service_root
    service_root_hash = hashlib.sha256(service_root.encode()).hexdigest()
    state_file = f'analyzed_files_{service_root_hash}.pickle'
    
    try:
        with open(state_file, 'rb') as state_f:
            analyzed_files, vulnerabilities = pickle.load(state_f)
    except FileNotFoundError:
        pass

    for file_description in tqdm(files):
        if file_description.path in [analyzed_file.path for analyzed_file in analyzed_files]:
            continue

        file_vulnerabilities = analyze_file(service_root, file_description, directories, debug=debug)
        for file_vulnerability in file_vulnerabilities:
            print(file_vulnerability)
            print()

        output.write(
            '\n\n'.join(
                str(file_vulnerability)
                for file_vulnerability in file_vulnerabilities
            )
        )
        output.flush()

        vulnerabilities.extend(file_vulnerabilities)

        # Update state file with the analyzed file
        analyzed_files.append(file_description)
        with open(state_file, 'wb') as state_f:
            pickle.dump([analyzed_files, vulnerabilities], state_f, fix_imports=True)

    return vulnerabilities

if __name__ == '__main__':
    output_file = f'vulnerabilities_{hashlib.sha256(SERVICE_ROOT.encode()).hexdigest()}.txt'
    with open(output_file, 'a') as output:
        vulnerabilities = analyze_vulnerability(SERVICE_ROOT, output, debug=False)
