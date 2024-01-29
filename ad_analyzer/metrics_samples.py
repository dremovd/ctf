from description import Vulnerability

def extract_code(file_path, line_numbers):
    with open(file_path) as f:
        lines = f.readlines()
        return "".join([
            f'{line_number}:\t{lines[line_number - 1]}'
            for line_number in line_numbers
        ])

source_labeled = [
    ("metrics_source/2023-service-sibirctf-sx/auth.py", [
        Vulnerability(
            root=None,
            path=None,
            relevant_code=extract_code("metrics_source/2023-service-sibirctf-sx/auth.py", range(16, 24)),
            name="Timing attack",
            description="The password comparison function 'check_password' uses a time-based comparison, which can be exploited using a timing attack to guess the password. An attacker can measure how long it takes for the function to return False and deduce the correct password one character at a time",
            severity=None,
            code_fix=None,
        ),
    ]),
    ("metrics_source/2023-service-sibirctf-sx/nginx.conf", [
        Vulnerability(
            root=".",
            path="auth.py",
            relevant_code=extract_code("metrics_source/2023-service-sibirctf-sx/auth.py", range(11, 14)),
            name="Path traversal",
            description="Missed '/' at the end of nginx location path",
            severity=None,
            code_fix=None,
        ),
    ]),
    ("metrics_source/2023-service-sibirctf-sx/post.py", [
        Vulnerability(
            root=".",
            path="post.py",
            relevant_code=extract_code("metrics_source/2023-service-sibirctf-sx/auth.py", [12, 40]),
            name="Missing Function Level Access Control",
            description="Protected class method is accessible as a _PostManager__get_all",
            severity=None,
            code_fix=None,
        ),
    ]),
    ("metrics_source/2023-service-sibirctf-stickmarket/nginx.conf", [
        Vulnerability(
            root=".",
            path="nginx.conf",
            relevant_code=extract_code("metrics_source/2023-service-sibirctf-stickmarket/nginx.conf", [18, 19, 20, 22, 23, 24]),
            name="Missing Function Level Access Control",
            description="Protected class method is accessible as a _PostManager__get_all",
            severity=None,
            code_fix=None,
        ),
    ]),
    ("metrics_source/2023-service-sibirctf-stickmarket/supervisor.conf", [
        Vulnerability(
            root=".",
            path="supervisor.conf",
            relevant_code=extract_code("metrics_source/2023-service-sibirctf-stickmarket/supervisor.conf", [17]),
            name="Backdoor",
            description="php8.1.0-dev backdoor",
            severity=None,
            code_fix=None,
        ),
    ]),

]
