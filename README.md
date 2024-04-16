# VirusTotal Command-Line Scanner

A command-line utility to scan files through the VirusTotal API v3

## Setting Up

### Dependencies

The script uses the requests module. You can download the module by running the following command:

```code
pip install requests
```

### API Key

The script uses the VirusTotal API. In order to use the API you must sign up to [VirusTotal Community](https://www.virustotal.com/gui/join-us). Once you have a valid VirusTotal Community account you will find your personal API key in your personal settings section. This key is all you need to use the VirusTotal API

Once you have the API key you will need to put it in the `--api_key` command line parameter,

NOTE: Do not share your API Key with anyone. Learn more about securing an API key [here.](https://cloud.google.com/docs/authentication/api-keys#securing_an_api_key)

## Usage

```code
usage: virustotal.py [-h] file
```

### Scanning a file

You scan a file by providing the file path to it.

```code
virustotal.py --api_key <YOUR_API_KEY> --file /path/to/file
```

Batch scanning with saving the results to a csv-file

```code
virustotal.py --api_key <YOUR_API_KEY> --folder /folder/to/scan/recursively --output_format csv --output_path /path/to/output.csv
```

Batch scanning with saving the results to a json-file

```code
virustotal.py --api_key <YOUR_API_KEY> --folder /folder/to/scan/recursively --output_format json --output_path /path/to/output.json
```

## How does the script work

The script uses VirusTotal API to scan files.

The script makes a GET request with the SHA 256 hash of the file. If no information about the file is returned or a 404 response code is sent back, then the script will upload the file to VirusTotal and wait for the analysis report. Once the analysis report is available, the script will again make a GET request against the SHA 256 of the same file and display the output.
