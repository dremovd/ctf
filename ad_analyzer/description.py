from typing import Dict

__all__ = ['Vulnerability', 'Directory', 'File']

class Vulnerability(object):
    def __init__(self, path: str, line: int, relevant_code:str, name: str, description: str, possible_fix: str) -> None:
        self.name = name
        self.description = description
        self.path = path
        self.line = line
        self.relevant_code = relevant_code
        self.possible_fix = possible_fix

    def __str__(self) -> str:
        return '\n'.join([
            f'Path: {self.path}',
            f'Vulnerability: {self.name}',
            f'Code line: {self.name}',
            f'Relevant code: {self.name}',
            f'Description: {self.description}',
            f'Possible fix: {self.possible_fix}',
        ])

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
    def __init__(self, path: str, lines_count: int, extension: str, is_binary: bool) -> None:
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