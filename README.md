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

`pip install beautifulsoup4 openai google-cloud-aiplatform requests regex google-generativeai google-auth google-auth-oauthlib google-auth-httplib2`


🚀 Usage

Run the application with:

python main.py  # Python example
npm start  # Node.js example

📜 Configuration

Add any necessary environment variables.

Modify config.json or .env if needed.


