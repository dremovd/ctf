from typing import List, Tuple
import os

import openai

from secret import openai_key
from prompting import chagpt_analyze
from description import Vulnerability, File, Directory

openai.api_key = openai_key
SERVICE_ROOT = '/Users/dmitry/projects/ctf-training/training/training'

from typing import List, Tuple
import os

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
    for root, dirs, filenames in os.walk(service_root):
        relative_root = os.path.relpath(root, service_root)
        directory_description = Directory(
            path=relative_root,
            files_count=len(filenames),
            subdirectories_count=len(dirs),
        )
        directories.append(directory_description)
        project_structure.append(directory_description)

        if debug:
            print(directory_description)
        
        for filename in filenames:
            filepath = os.path.join(root, filename)
            relative_filepath = os.path.relpath(filepath, service_root)
            extension = os.path.splitext(filename)[1]
            lines_count = sum(1 for line in open(filepath, 'r', encoding='utf-8', errors='ignore')) if not is_binary_file(filepath) else 0
            file_description = File(
                path=relative_filepath, 
                lines_count=lines_count,
                extension=extension, 
                is_binary=is_binary_file(filepath)
            )
            files.append(file_description)
            project_structure.append(file_description)
            if debug:
                print(file_description)

    return directories, files, project_structure

def analyze_file(service_root: str, file_description: File, project_structure: List(File | Directory), debug: bool = False) -> List[Tuple(File, Vulnerability)]:
    """Using simple completion to obtain vulnerability analysis"""
    vulnerabilities = []
    if file_description.is_binary:
        return vulnerabilities  # Skip binary files

    filepath = os.path.join(service_root, file_description.path)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
        code = file.read()

    vulnerabilities = chagpt_analyze(code, project_structure, debug=debug)

    return vulnerabilities


def analyze_vulnerability(service_root: str, debug=False) -> List[Tuple(File, Vulnerability)]:
    directories, files, project_structure = list_service_directory(service_root, debug=True)
    vulnerabilities = []
    for file_description in files:
        file_vulnerabilities = analyze_file(service_root, file_description, project_structure, debug=True)
        vulnerabilities.extend(file_vulnerabilities)

    return vulnerabilities

if __name__ == '__main__':
    vulnerabilities = analyze_vulnerability(SERVICE_ROOT, debug=True)
    for vulnerability in vulnerabilities:
        print(vulnerability)