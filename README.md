# PROBER-M1: An Algorithm for Vulnerability Fixes and Relevant Data Identification

## Overview 
Prober is an AI-powered tool designed to identify and extract vulnerability-fixing commits in open-source projects. Detecting patch or fix commits is crucial, as it provides users with essential information on whether a security issue has been addressed.

In addition to identifying fix commits, Prober also provides:

- Fixed versions of the software

- Affected source files and functions

- AI-generated, focused vulnerability descriptions

Prober leverages large language models (LLMs) such as OpenAI and Gemini to enhance its analysis. It sources vulnerability data from trusted repositories, including the National Vulnerability Database (NVD) and Open Source Vulnerabilities (OSV) database.

## Features

Feature 1

Feature 2

Feature 3
 Installation

## Steps

1. Clone the repository:

`git clone https://github.com/ejaz629/Prober-M1.git`

2. Navigate to the project directory:

`cd Prober-M1`

Install dependencies:

`pip install beautifulsoup4 openai google-cloud-aiplatform requests regex google-generativeai google-auth google-auth-oauthlib google-auth-httplib2 argparse`


## Usage
Run the application with:  
```sh
 python prober.py --cve CVE-2025-21893 --ai-model openai

### You can specificy three flags for specific data.

### Required Arguments  
- **`--cve` (REQUIRED)**:  
  Specify the CVE identifier. Prober supports all CVE formats from [OSV.dev](https://osv.dev/).  
  **Example:**  
  ```sh
  --cve CVE-2025-21893

- **`--ai-model` (REQUIRED)**:
Select the AI model to use. Available options are Gemini and OpenAI.
  1. Gemini Model: `gemini-1.5-flash-002`
  2. OpenAI Model: `gpt-4-turbo`
  
  **Example:**
  ```sh
  --ai-model openai

### Optional Arguments
- **`--source` (OPTIONAL)**:
Specify the data source when OSV lacks records for a vulnerability. If set, Prober will use the NVD API to fetch data.
Available options: 'osv' (default) or 'nvd'.

  **Example:**
  ```sh 
   --source osv


## Configuration

Add any necessary environment variables and API keys. Please check config.py for the required data.


