from typing import List, Tuple, Dict, Optional
import json
import time

import openai

from description import Vulnerability, File, Directory
from examples import examples  

from secret import openai_key
openai.api_key = openai_key

from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

def normalize_output(text):
    paragraphs = text.split('\n')
    paragraphs = [p.strip() for p in paragraphs if p.strip()]
    return '\n'.join(paragraphs)

def normalize_code_output(text):
    paragraphs = text.split('\n')
    paragraphs = [p.rstrip() for p in paragraphs if p.strip()]
    return '\n'.join(paragraphs)

def normalize_text(text):
    paragraphs = text.split('\n')
    paragraphs = [p.strip() for p in paragraphs]
    return '\n'.join(paragraphs)

def normalize_paragraph(paragraph):
    sentences = paragraph.split('\n')
    sentences = [s.strip() for s in sentences if s.strip()]
    return ' '.join(sentences)


examples_formatted = "\n\n".join([
    f"OUTPUT EXAMPLE {i + 1}:\n{json.dumps(example, separators=(',', ':'), indent=2)}" 
    for i, example in enumerate(examples)
])
system_prompt = """
TASK:
Position: Cybersecurity Expert.
Goal: Prevent unauthorized data exploitation in a web project after source code exposure.
Input: JSON format including:
- PROJECT_STRUCTURE: Detailed map of project's file and directory structure.
- FILE_DESCRIPTION: Specifics and metadata of each file.
- CODE: The complete source code with line numbers.
- VULNERABILITIES_CHECKLIST: Required checklist for vulnerability scanning.

RESPONSE FORMAT:
Your response should be a JSON file encapsulating:
- relevant_code: <Vulnerable code segments with line references>
- name: <Type of vulnerability detected>
- description: <Elaborate explanation of each vulnerability>
- severity: <Risk assessment regarding unauthorized data access>
- code_fix: <Proposed code changes in .diff format to address the vulnerability>

{examples_formatted}

NOTE:
Thoroughly scrutinize every part of the source code, including configuration files, functions, and methods. In each analysis, focus on identifying the most severe vulnerability. Responses must strictly be in JSON format, listing vulnerabilities only.
"""

print(system_prompt)

checklist = """
    Injection Attacks - Untrusted data sent to an interpreter; Look for unsanitized input in SQL queries, OS commands, etc.
    Broken Authentication - Incomplete or incorrect implementation of authentication; Check for weak passwords, session management, etc.
    Sensitive Data Exposure - Unprotected sensitive information; Look for weak encryption, exposed API keys, etc.
    Cross-Site Scripting (XSS) - Untrusted data inserted into HTML; Look for unsanitized user input in HTML content.
    Broken Access Control - Users able to perform unauthorized actions; Verify role-based access controls, direct object references, etc.
    HTTP Verb Tampering - Exploiting alternative HTTP methods; Check for proper handling and filtering of HTTP methods like POST, PUT, DELETE.
    Parameter Tampering - Manipulation of parameters in URL, cookies, request body; Look for improper validation of parameters and strict method handling.
    Security Misconfiguration - Default, incomplete, or ad-hoc configurations; Check for unnecessary services, default credentials, etc.
    Insecure Deserialization - Untrusted data affecting object creation; Check serialization methods, object creation, etc.
    XML External Entity (XXE) - External entity references in XML; Check XML parsers for external entity inclusion.
    Path Traversal Attack - Accessing files and directories outside the intended directory; Look for unfiltered user input in file paths.
    Insecure Direct Object References (IDOR) - Access to unauthorized objects; Check object references without proper access controls.
    Server-Side Request Forgery (SSRF) - Requests sent to internal resources; Look for user-supplied URLs affecting server requests.
    Unvalidated Redirects and Forwards - Redirecting to untrusted URLs; Check for user parameters in redirects.
    Insecure Data Storage - Inadequate protection of stored data; Check for proper encryption and access controls on stored data.
    Weak Cryptography - Using weak or outdated cryptographic algorithms; Verify algorithms used for encryption, hashing, etc.
    Uncontrolled Resource Consumption - Leading to Denial of Service; Look for lack of rate limiting, resource-intensive operations, etc.
    Unvalidated File Uploads - Malicious file uploads; Check for lack of file type validation, improper permissions, etc.
    Exposed Administrative Interfaces - Unprotected admin panels; Look for lack of authentication on administrative endpoints.
    Hardcoded Secrets - Credentials or secrets in code; Check source code for hardcoded passwords, API keys, etc.
    Missing Function Level Access Control - Inadequate protection of functions; Check for exposed internal functions, lack of authentication, etc.
    API Security Misconfiguration - Inadequate protection of APIs; Check for weak authentication, lack of input validation in APIs.
    Information Leakage - Exposing sensitive information in errors, etc.; Check for detailed error messages, stack traces, etc.
    Improper Certificate Validation - Ignoring or mishandling certificate errors; Check for improper SSL certificate validation.
"""
dict_prompt = """{dict_input}"""

llm = ChatOpenAI(
    openai_api_key=openai_key,
    model='gpt-4-1106-preview',
    temperature=0,
    max_tokens=4096,
)

prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    ("user", dict_prompt),
])

output_parser = StrOutputParser()
chain_solution = prompt | llm | output_parser

def chagpt_analyze(file_description: File, code: str, project_structure: List[File | Directory], debug=False):
    dict_input = str({
        "PROJECT_STRUCTURE": [entity.as_dict() for entity in project_structure],
        "FILE_DESCRIPTION": file_description.as_dict(),
        "CODE": code,
        "VULNERABILITIES_CHECKLIST": [line.strip() for line in checklist.split('\n') if line.strip()][:30],
    })

    response = chain_solution.invoke({
        "dict_input": dict_input,
        "examples_formatted": examples_formatted,
    }).strip()
    if response.startswith('```json'):
        response = response[7:].strip()
    if response.endswith('```'):
        response = response[:-3].strip()

    vulnerabilities = []
    try:
        vulnerabilities_dict = json.loads(response)
    except json.decoder.JSONDecodeError:
        return vulnerabilities

    if isinstance(vulnerabilities_dict, dict):
        vulnerabilities_dict = [vulnerabilities_dict]

    for vulnerability_dict in vulnerabilities_dict:
        try:
            vulnerability = Vulnerability(
                root=file_description.root,
                path=file_description.path,
                relevant_code=vulnerability_dict.get('relevant_code', None),
                name=vulnerability_dict.get('name', None),
                description=vulnerability_dict.get('description', None),
                severity=vulnerability_dict.get('severity', None),
                code_fix=vulnerability_dict.get('code_fix', None),
            )
        except AttributeError:
            print(f'RESPONSE FORMAT ERROR:\n{vulnerability_dict}')

        vulnerabilities.append(vulnerability)
    return vulnerabilities


if __name__ == '__main__':
    test_file_description = File(
        root=".",
        path="test.py",
        lines_count=2,
        extension=".py",
        is_binary=False,
    )
    result = chagpt_analyze(file_description=test_file_description, code="# Test code\n\nprint('Hello world!')", project_structure=[test_file_description], debug=True)
    print(result)