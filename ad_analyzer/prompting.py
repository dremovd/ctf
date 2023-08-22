from typing import List, Tuple, Dict, Optional
import json
import time

import openai

from description import Vulnerability, File, Directory

from secret import openai_key
openai.api_key = openai_key

models = [value['id'] for value in openai.Model.list()['data']]
print('\n'.join(sorted([model for model in models if model.startswith('gpt')])))

gpt4_models = ['gpt-4-0613', 'gpt-4'] 
assert all(model in models for model in gpt4_models)
current_gpt4_model_index = 0

gpt3_models = ['gpt-3.5-turbo', 'gpt-3.5-turbo-0613']
assert all(model in models for model in gpt3_models)
current_gpt3_model_index = 0


MODEL_PRICES = {
    "input_token": 0.001 * 0.03,
    "output_token": 0.001 * 0.06,
}
RATE_LIMIT_DELAY = 20
UNAVAILABLE_LIMIT_DELAY = 10

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

"""Helper function for generating text using the OpenAI API."""

def chat_generate_text(
    prompt: str,
    model: str = "gpt-3.5-turbo",
    system_prompt: str = "You are a helpful assistant.",
    temperature: float = 0,
    max_tokens: int = 2048,
    n: int = 1,
    stop: Optional[str | list] = None,
    presence_penalty: float = 0,
    frequency_penalty: float = 0.1,
    debug=False,
) -> List[str]:
    """
    chat_generate_text - Generates text using the OpenAI API.
    :param str prompt: prompt for the model
    :param str openai_api_key: api key for the OpenAI API, defaults to None
    :param str model: model to use, defaults to "gpt-3.5-turbo"
    :param str system_prompt: initial prompt for the model, defaults to "You are a helpful assistant."
    :param float temperature: _description_, defaults to 0
    :param int max_tokens: _description_, defaults to 1024
    :param int n: _description_, defaults to 1
    :param Optional[Union[str, list]] stop: _description_, defaults to None
    :param float presence_penalty: _description_, defaults to 0
    :param float frequency_penalty: _description_, defaults to 0.1
    :return List[str]: _description_
    """
    messages = [
        {"role": "system", "content": f"{system_prompt}"},
        {"role": "user", "content": prompt},
    ]

    if debug:
        print("DEBUG: messages")
        for message in messages:
            print("ROLE: {role}\nCONTENT:\n```{content}```".format(**message))

    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        n=n,
        stop=stop,
        presence_penalty=presence_penalty,
        frequency_penalty=frequency_penalty,
    )

    generated_texts = [
        choice.message["content"].strip() 
        for choice in response["choices"]
    ]
    if debug:
        cost = (
            MODEL_PRICES["input_token"] * response['usage']['prompt_tokens']
            + MODEL_PRICES["output_token"] * response['usage']['completion_tokens']
        )
        print(f"API cost: ${cost}")

    return generated_texts


def simple_completion(dict_input: Dict, system_prompt: str, debug: bool=False, needs_gpt4=False, temperature : float=0):
    if debug:
        print("PROMPT:")
        print(system_prompt)

        print("INPUT:")
        print(json.dumps(dict_input, separators=(',', ':'), indent=2))
        print()

    input = json.dumps(dict_input, separators=(',', ':'))

    max_retries = 3
    retries = 0
    while retries < max_retries:
        try:
            if needs_gpt4:
                global current_gpt4_model_index
                model = gpt4_models[current_gpt4_model_index % len(gpt4_models)]
                current_gpt4_model_index += 1
            else:
                global current_gpt3_model_index
                model = gpt3_models[current_gpt3_model_index % len(gpt3_models)]
                current_gpt3_model_index += 1
            if debug:
                print(f'Using model {model}')
            results = chat_generate_text(
                prompt=input,
                model=model,
                system_prompt=system_prompt,
                debug=debug,
                temperature=temperature,
                n=1,
            )
            return normalize_code_output(results[0])
        except openai.error.RateLimitError as e:
            print(f"RateLimitError occurred. Retrying in {RATE_LIMIT_DELAY} seconds...")
            time.sleep(RATE_LIMIT_DELAY)
        except openai.error.ServiceUnavailableError:
            print(f"ServiceUnavailableError occurred. Retrying in {UNAVAILABLE_LIMIT_DELAY} seconds...")
            time.sleep(UNAVAILABLE_LIMIT_DELAY)            
        except openai.error.APIError as e:
            if e.args[0] == 502 and 'Bad gateway.' in str(e):
                if debug:
                    print(f"APIError occurred (Bad Gateway). Retrying {retries + 1} of {max_retries}...")
                retries += 1
                if retries == max_retries:
                    raise Exception("Maximum retries reached. Unable to complete the request due to Bad Gateway.")
                time.sleep(1)  # Optional delay before retrying
            else:
                raise e  # Re-raise the exception if it's not the specific error we're handling

system_prompt = """
    TASK:
    You are an information security specialist.
    You need to prevent unauthorized data access for a web project. 
    This project source code was leaked.
    Your input formatted as a JSON with the following structure:
    - PROJECT_STRUCTURE: A project structure as a list of directories and file names.
    - FILE_DESCRIPTION: File properties.
    - CODE: A source code of the project.
    - VULNERABILITIES_CHECKLIST: A checklist for vulnurabities you need to check. You need to check all of them, but you are not limited to them.

    RESPONSE FORMAT:
    Your response shoule be strictly formatted as a JSON file with the following structure:
    List of vulnerabilities, each of the following structure: 
    - relevant_code: <source code line in vulnerability : str>
    - name: <vulnerability name : str>
    - description: <vulnerability description : str>
    - severity: <how simple is to get unauthorized data using this vulnerability: str>
    - code_fix: <changes in the relevant code needed to fix vulnerability : str>

    NOTE:
    Please, strictly check all the source code including configuration, each function and each class method.
    For each block of source code output only the most severe vulnerability.
    Please, strictly output only JSON formatted list of vulnerabilities.
"""

checklist = """
    Injection Attacks - Untrusted data sent to an interpreter; Look for unsanitized input in SQL queries, OS commands, etc.
    Broken Authentication - Incomplete or incorrect implementation of authentication; Check for weak passwords, session management, etc.
    Sensitive Data Exposure - Unprotected sensitive information; Look for weak encryption, exposed API keys, etc.
    Cross-Site Scripting (XSS) - Untrusted data inserted into HTML; Look for unsanitized user input in HTML content.
    Broken Access Control - Users able to perform unauthorized actions; Verify role-based access controls, direct object references, etc.
    HTTP Verb Tampering - Exploiting alternative HTTP methods; Check for proper handling and filtering of HTTP methods like POST, PUT, DELETE.
    Parameter Tampering - Manipulation of parameters in URL, cookies, request body; Look for improper validation of parameters and strict method handling.
    Security Misconfiguration - Default, incomplete, or ad-hoc configurations; Check for unnecessary services, default credentials, etc.
    Using Components with Known Vulnerabilities - Using outdated libraries; Check versions of third-party components and libraries.
    Insecure Deserialization - Untrusted data affecting object creation; Check serialization methods, object creation, etc.
    XML External Entity (XXE) - External entity references in XML; Check XML parsers for external entity inclusion.
    Cross-Site Request Forgery (CSRF) - Forged requests made by user; Look for lack of anti-CSRF tokens in forms.
    Path Traversal Attack - Accessing files and directories outside the intended directory; Look for unfiltered user input in file paths.
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
        "PROJECT_STRUCTURE": [entity.as_dict() for entity in project_structure],
        "FILE_DESCRIPTION": file_description.as_dict(),
        "CODE": code,
        "VULNERABILITIES_CHECKLIST": [line.strip() for line in checklist.split('\n') if line.strip()][:30],
    }

    response = simple_completion(dict_input, system_prompt, debug=debug, needs_gpt4=True)
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
                line=None,
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
    chagpt_analyze(file_description=test_file_description, code="# Test code\n\nprint('Hello world!')", project_structure=[test_file_description], debug=True)