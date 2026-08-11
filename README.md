# DNSTOOL
Tool for testing DNS record settings
Author Adam Šopík, xsopik03

## Setup

- In root folder create virtual environment (python3 -m venv venv)
- activate virtual environment (.\venv\Scripts\activate)
- install requirements (pip install -r requirements.txt)
- install application locally (pip install -e .)
- run the app

## Usage
Basic scan:

`dnstool domain.com`

By default, the tool queries all configured data sources and returns a unified DNS view.

JSON output for penterep/platform integrations:

`dnstool example.com -j`

Write JSON and CSV files:

`dnstool example.com -j --json-file out.json --csv-file out.csv`

Select a source:

`dnstool example.com --source intodns_ai`

Available sources are `zonemaster`, `intodns`, `intodns_ai`, and `mxtoolbox`.

Environment variables for source configuration:

- `INTODNS_AI_API_BASE_URL` defaults to `https://intodns.ai/api`
- `INTODNS_AI_API_TIMEOUT` defaults to `30`
- `INTODNS_AI_API_LANGUAGE` defaults to `en`

 For more use the help command 
 
 `dnstool -h`
