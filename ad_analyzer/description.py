from typing import Dict
import os
import re

__all__ = ['Vulnerability', 'Directory', 'File']

line_number_re = re.compile(r'^(\d+):')
class Vulnerability(object):
    def __init__(self, root:str, path: str, relevant_code : str=None, name: str=None, description: str=None, severity: str=None, code_fix: str=None) -> None:
        self.path = path
        self.relevant_code = relevant_code
        self.name = name
        self.description = description
        self.severity = severity
        self.code_fix = code_fix
        self.root = root
        self.line_numbers = []
        for line in relevant_code.split("\n"):
            match = line_number_re.match(line)
            if match:
                self.line_numbers.append(int(match.group(1)))

    def __str__(self) -> str:
        code = '\n'.join([line for line in self.relevant_code.split("\n") if line.strip()])
        line_numbers = ",".join(map(str, self.line_numbers))
        lines = [
            f'Direct code link: {os.path.join(self.root, self.path)}',
            f'Path: {self.path}',
            f'Vulnerability: {self.name}',
            f'Code lines: {line_numbers}',
            f'Relevant code:\n{code}',
            f'Description: {self.description}',
            f'Severity: {self.severity}',
            f'Fix: {self.code_fix}',
        ]
        return '\n'.join(line for line in lines if not line.endswith('None'))
    
    def as_dict(self) -> Dict:
        return {
            'path': self.path,
            'line_numbers': self.line_numbers,
            'relevant_code': self.relevant_code,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'code_fix': self.code_fix,
            'root': self.root,
        }

class Directory(object):
    def __init__(self, path: str, files_count: int, subdirectories_count: int) -> None:
        self.path = path
        self.files_count = files_count
        self.subdirectories_count = subdirectories_count

    def __str__(self) -> str:
        return f'Directory(path="{self.path}", files_count={self.files_count}, subdirectories_count={self.subdirectories_count})'
    
    def as_dict(self) -> Dict:
        return {
            'path': self.path,
            'files_count': self.files_count,
            'subdirectories_count': self.subdirectories_count,
        }
    
class File(object):
    def __init__(self, root:str, path: str, lines_count: int, extension: str, is_binary: bool) -> None:
        self.root = root
        self.path = path
        self.lines_count = lines_count
        self.extension = extension
        self.is_binary = is_binary

    def __str__(self) -> str:
        return f'File(path="{self.path}", lines_count={self.lines_count}, extension="{self.extension}", is_binary={self.is_binary})'

    def as_dict(self) -> str:
        return {
            'path': self.path,
            'lines_count': self.lines_count,
            'extension': self.extension,
            'is_binary': self.is_binary,
        }