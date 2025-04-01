# PROBER-M1: An Algorithm for Vulnerability Fixes and Relevant Data Identification

## Overview 
Prober is a novel method for progressively and iteratively parsing GitHub pages, including relevant references on each GitHub issue and PR link, to extract the most relevant information regarding a given CVE identifier. Prober is an AI-powered tool designed to identify and extract vulnerability-fixing commits in open-source projects. Detecting patch or fix commits is crucial, as it provides users with essential information on whether a security issue has been addressed.

In addition to identifying fix commits, Prober also provides:

- Fixed versions of the software

- Affected source files and functions

- AI-generated, focused vulnerability descriptions

Prober leverages large language models (LLMs) such as OpenAI and Gemini to enhance its analysis. It sources vulnerability data from trusted repositories, including the National Vulnerability Database (NVD) and Open Source Vulnerabilities (OSV) database.

## Key Features of Prober

- AI-Powered Analysis: Supports LLMs like Gemini and OpenAI, enabling Prober to leverage multiple AI models for extracting vulnerability insights from unstructured data.

- Real-time Processing: Performs all processing in real-time and at scale. 

- Multi-Source Data Integration: Considers multiple sources of input data, such as OSV.dev and NVD, for comprehensive vulnerability assessment.

## Steps

1. Clone the repository:

`git clone https://github.com/ejaz629/Prober-M1.git`

2. Navigate to the project directory:

`cd Prober-M1`

Install dependencies:

`pip install beautifulsoup4 openai google-cloud-aiplatform requests regex google-generativeai google-auth google-auth-oauthlib google-auth-httplib2 argparse`


## Usage
Run the application with:  
`python prober.py --cve CVE-2025-21893 --source osv --ai-model openai`

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

## Output  

When running the command `python prober.py --cve CVE-2025-21893 --ai-model openai`, the tool extracts and provides detailed CVE information.  

Example output:  

### Extracted CVE Information

```json
{
  "cve_id": "CVE-2025-21893",
  "prober-generated-cve-desc": "CVE-2025-21893: In the Linux kernel, a Use-After-Free (UAF) vulnerability in key_put() function has been resolved. Once a key's reference count is reduced to 0, the garbage collector thread may destroy it, hence key_put() should not access the key beyond this point.",
  "prober-predicted-repo": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
  "osv_cve_desc": "In the Linux kernel, the following vulnerability has been resolved:\n\nkeys: Fix UAF in key_put()\n\nOnce a key's reference count has been reduced to 0, the garbage collector\nthread may destroy it at any time and so key_put() is not allowed to touch\nthe key after that point. The most key_put() is normally allowed to do is\nto touch key_gc_work as that's a static global variable.\n\nHowever, in an effort to speed up the reclamation of quota, this is now\ndone in key_put() once the key's usage is reduced to 0 - but now the code\nis looking at the key after the deadline, which is forbidden.\n\nFix this by using a flag to indicate that a key can be gc'd now rather than\nlooking at the key's refcount in the garbage collector.",
  "osv-git-repo": null,
  "analysed_pages": [
    "https://git.kernel.org/stable/c/6afe2ea2daec156bd94ad2c5a6f4f4c48240dcd3",
    "https://git.kernel.org/stable/c/75845c6c1a64483e9985302793dbf0dfa5f71e32",
    "https://git.kernel.org/stable/c/f6a3cf833188e897c97028cd7b926e3f2cb1a8c0",
    "https://security-tracker.debian.org/tracker/CVE-2025-21893"
  ],
  "fix_commits": "https://git.kernel.org/linus/75845c6c1a64483e9985302793dbf0dfa5f71e32",
  "fixed_versions": ["5.10.223-1", "5.10.234-1", "6.1.128-1", "6.1.129-1", "6.12.21-1"],
  "fix_exists": "Yes",
  "vulnerable_artifacts": {
    "files": ["include/linux/key.h", "security/keys/gc.c", "security/keys/key.c"],
    "functions": ["key_put"]
  }
}
```

## Contact  

For any questions, suggestions, or contributions, feel free to reach out:  

- **Maintainer**: Ejaz Ahmed  
- **Email**: [ejaz629@gmail.com](mailto:ejaz629@gmail.com)  
- **GitHub**: [ejaz629](https://github.com/ejaz629)  
- **LinkedIn**: [Profile](https://www.linkedin.com/in/ejaz629)  

To report issues, please use the [GitHub Issues](https://github.com/ejaz629/Prober-M1/issues) section.  




