### Email Parser script for bCIRT

The script is used to extract information fomr "eml" and "msg" files.

Supports Ubuntu, CentOS/RHEL, OpenSuse.

See the help for more details.

Install prerequisites:
pip3 install -r requirements.txt

Execute:

*python3 EmailParser_20200525.py --help*

usage: email_parser [options]

Process email file.

positional arguments:
  PATH                  Directory path to the file

optional arguments:

  -h, --help            show this help message and exit

  -p, --print           Print the analysis results

  -a SAVE-ATTACHMENT-TO, --attachment SAVE-ATTACHMENT-TO
                        Save attachments

  -b SAVE-BODY-TO, --savebody SAVE-BODY-TO
                        Save body contents to file

  -u URLS, --urls URLS  Print urls in body if 1, extract safelinks if 2

  --ipv4                Print IPv4 addresses in body and header

  -e, --emails          Print emails in body

  -j, --json            Print results in JSON format

