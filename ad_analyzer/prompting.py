from typing import List, Tuple, Dict
import json

from description import Vulnerability, File, Directory

def simple_completion(dict_input: Dict, system_prompt: str, debug):
    if debug:
        print("PROMPT:")
        print(system_prompt)

        print("INPUT:")
        print(json.dumps(dict_input, separators=(',', ':'), indent=2))
        print()

    str_input = json.dumps(dict_input, separators=(',', ':'))

    return "[]"

system_prompt = """
    TASK
    You are an information security specialist.
    You need to prevent unauthorized data access for a web project. 
    This project source code was leaked.
    Your input formatted as a JSON with the following structure:
    PROJECT_STRUCTURE: A project structure as a list of directories and file names.
    CODE: A source code of the project.
    VULNERABILITIES_CHECKLIST: A checklist for vulnurabities you need to check. You need to check all of them, but you are not limited to them.

    RESPONSE FORMAT:
    Your response shoule be strictly formatted as a JSON file with the following structure:
    List of vulnerabilities, each of the following structure: 
    - line: <source code line number in vulnerability : int>
    - relevant_code: <source code line in vulnerability : str>
    - name: <vulnerability name : str>
    - description: <vulnerability description : str>
    - possible_fix: <possible fix : str>

    Please, strictly do not output anything else in your response - only JSON formatted list of vulnerabilities.
"""

checklist = """
    Injection Attacks - Untrusted data sent to an interpreter; Look for unsanitized input in SQL queries, OS commands, etc.
    Broken Authentication - Incomplete or incorrect implementation of authentication; Check for weak passwords, session management, etc.
    Sensitive Data Exposure - Unprotected sensitive information; Look for weak encryption, exposed API keys, etc.
    Cross-Site Scripting (XSS) - Untrusted data inserted into HTML; Look for unsanitized user input in HTML content.
    Broken Access Control - Users able to perform unauthorized actions; Verify role-based access controls, direct object references, etc.
    Security Misconfiguration - Default, incomplete, or ad-hoc configurations; Check for unnecessary services, default credentials, etc.
    Using Components with Known Vulnerabilities - Using outdated libraries; Check versions of third-party components and libraries.
    Insecure Deserialization - Untrusted data affecting object creation; Check serialization methods, object creation, etc.
    XML External Entity (XXE) - External entity references in XML; Check XML parsers for external entity inclusion.
    Cross-Site Request Forgery (CSRF) - Forged requests made by user; Look for lack of anti-CSRF tokens in forms.
    Insecure Direct Object References (IDOR) - Access to unauthorized objects; Check object references without proper access controls.
    Server-Side Request Forgery (SSRF) - Requests sent to internal resources; Look for user-supplied URLs affecting server requests.
    Unvalidated Redirects and Forwards - Redirecting to untrusted URLs; Check for user parameters in redirects.
    Insufficient Logging and Monitoring - Lack of or ineffective logging; Ensure proper logging of authentication, access, etc.
    Insecure Data Storage - Inadequate protection of stored data; Check for proper encryption and access controls on stored data.
    Weak Cryptography - Using weak or outdated cryptographic algorithms; Verify algorithms used for encryption, hashing, etc.
    Uncontrolled Resource Consumption - Leading to Denial of Service; Look for lack of rate limiting, resource-intensive operations, etc.
    Misconfigured CORS - Improper Cross-Origin Resource Sharing; Verify CORS policies and proper origin validation.
    Clickjacking - Embedding UI into malicious sites; Check for lack of X-Frame-Options header.
    Unvalidated File Uploads - Malicious file uploads; Check for lack of file type validation, improper permissions, etc.
    Exposed Administrative Interfaces - Unprotected admin panels; Look for lack of authentication on administrative endpoints.
    Hardcoded Secrets - Credentials or secrets in code; Check source code for hardcoded passwords, API keys, etc.
    Password Management Weaknesses - Insecure handling of passwords; Look for lack of hashing, weak password policies, etc.
    Missing Function Level Access Control - Inadequate protection of functions; Check for exposed internal functions, lack of authentication, etc.
    Open Redirects - Redirecting to malicious sites; Check for unvalidated user input in redirect URLs.
    API Security Misconfiguration - Inadequate protection of APIs; Check for weak authentication, lack of input validation in APIs.
    Information Leakage - Exposing sensitive information in errors, etc.; Check for detailed error messages, stack traces, etc.
    Inadequate Transport Layer Protection - Weak encryption during data transfer; Look for outdated TLS, weak ciphers, etc.
    Abuse of Functionality - Misusing application functions; Look for lack of proper rate limiting, role checks, etc.
    Improper Certificate Validation - Ignoring or mishandling certificate errors; Check for improper SSL certificate validation.
"""

def chagpt_analyze(file_description: File, code: str, project_structure: List[File | Directory], debug=False):
    dict_input = {
        "CODE": code,
        "PROJECT_STRUCTURE": [entity.as_dict() for entity in project_structure],
        "VULNERABILITIES_CHECKLIST": [line.strip() for line in checklist.split('\n') if line.strip()][:10],
    }

    response = simple_completion(dict_input, system_prompt, debug)
    vulnerabilities_dict = json.loads(response)
    vulnerabilities = []
    for vulnerability_dict in vulnerabilities_dict:
        vulnerability = Vulnerability(
            path=file_description.path,
            line=vulnerability_dict['line'],
            relevant_code=vulnerability_dict['relevant_code'],
            name=vulnerability_dict['name'],
            description=vulnerability_dict['description'],
        )
        vulnerabilities.append(vulnerability)
    return vulnerabilities


if __name__ == '__main__':
    test_file_description = File(
        path="test.py",
        lines_count=2,
        extension=".py",
        is_binary=False,
    )
    chagpt_analyze(file_description=test_file_description, code="# Test code\n\nprint('Hello world!')", project_structure=[test_file_description], debug=True)