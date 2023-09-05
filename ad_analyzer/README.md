
# Ad Analyzer Project

## Overview

The Ad Analyzer Project is a comprehensive tool for analyzing code files for vulnerabilities. It employs GPT-4 and OpenAI's API for its analysis. The project has evolved to include functionalities for handling argument parsing, file traversal, and vulnerability analysis.

## Table of Contents

- [Files](#files)
  - [analyzer.py](#analyzerpy-updated)
  - [description.py](#descriptionpy-updated)
  - [prompting.py](#promptingpy-updated)
- [Dependencies](#dependencies)
- [Usage](#usage)

## Files

### `analyzer.py` (Updated)

#### Purpose
This is the central file for the project. It not only drives the code analysis but also manages file traversal and argument parsing. It also stores a state file to keep track of already analyzed files.

#### Functions
- `parse_arguments`: Parses command-line arguments, specifically the service root directory.
- `is_binary_file`: Checks if a file is binary. Reads the first 1024 bytes and checks for null bytes.
- `list_service_directory`: Lists all directories and files in the service root directory. It also gathers statistical data like the number of files and subdirectories.
- `analyze_file`: Analyzes each file for vulnerabilities. It uses the `chagpt_analyze` function from `prompting.py` for the GPT-based analysis.
- `analyze_vulnerability`: Orchestrates the overall vulnerability analysis, including reading the state file to avoid re-analyzing files.

#### Additional Features
- Utilizes a state file to store analyzed files and found vulnerabilities.
- Uses a unique hash for each service root to store state and output files.

#### Dependencies
- `typing`, `os`, `tqdm`, `pickle`, `hashlib`, `argparse`, `prompting`, `description`, `tiktoken`

---

### `description.py` (Updated)

#### Purpose
The file defines classes for representing vulnerabilities, directories, and files within the scope of the project. These classes act as the data models for the project.

#### Functions
- `__init__`: Initializes class objects with specific attributes like `path`, `lines_count` for `File`, and `name`, `description`, `severity` for `Vulnerability`.
- `__str__`: Provides a string representation of the class object. Particularly useful for debugging or logging.
- `as_dict`: Converts the class object to a dictionary, making it easier to serialize or display.

#### Classes
- `Vulnerability`: Represents a code vulnerability with attributes like `path`, `line`, `relevant_code`, `name`, `description`, `severity`, and `code_fix`.
- `Directory`: Represents a directory with attributes like `path`, `files_count`, and `subdirectories_count`.
- `File`: Represents a file with attributes like `path`, `lines_count`, `extension`, and `is_binary`.

#### Additional Features
- `Vulnerability` class includes a `root` attribute that allows for generating direct code links.
- All classes have an `as_dict` method for easy serialization.

#### Dependencies
- `typing`, `os`

---

### `prompting.py` (Updated)

#### Purpose
This file is responsible for all interactions with the OpenAI API. It handles text generation, rate-limiting, and model selection. It also provides utility functions for text normalization.

#### Functions
- `normalize_output`: Normalizes the text output from the API, removing unnecessary spaces and newlines.
- `normalize_code_output`: Similar to `normalize_output`, but specific to code text.
- `normalize_text`: A general text normalization function.
- `normalize_paragraph`: Normalizes a paragraph by removing unnecessary spaces between sentences.
- `chat_generate_text`: A complex function for generating text using the OpenAI API. It includes various parameters like `temperature`, `max_tokens`, and others for fine-grained control.
- `chagpt_analyze`: The main function for analyzing a file for vulnerabilities. It prepares the input, calls the API, and processes the response to extract vulnerabilities.

#### Additional Features
- Handles multiple GPT-3 and GPT-4 models.
- Includes token pricing calculations for OpenAI API usage.
- Implements rate-limiting and handles API unavailability.
- Supports debugging modes.

#### Dependencies
- `typing`, `json`, `time`, `openai`, `description`

---

## Dependencies

- `typing`
- `os`
- `tqdm`
- `pickle`
- `hashlib`
- `argparse`
- `openai`
- `json`
- `time`
- `tiktoken`

## Usage

(TBD)

## Usage

### Running the Application Directly with Python

To run the application directly using Python, navigate to the project directory and run the following command:

\`\`\`bash
python analyzer.py --service-root /path/to/service/source
\`\`\`

### Running the Application with Docker

1. Build the Docker image:

\`\`\`bash
docker build -t ad-analyzer .
\`\`\`

2. Run the Docker container:

\`\`\`bash
docker run ad-analyzer --service-root /path/to/service/source
\`\`\`

In both examples, replace `/path/to/service/source` with the actual path to the service source code you want to analyze.
