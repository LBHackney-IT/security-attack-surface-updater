#!/usr/bin/env python

import os
import re
import gspread
from slack_sdk.webhook import WebhookClient

def load_google_sheet(url, sheet_title="Sheet1", credentials_file="./google_service_account_credentials.json"):
    """Loads a Google Sheet and returns the contents of the sheet as an array of dictionaries"""
    google_service_account = gspread.service_account(filename=credentials_file)

    workbook = google_service_account.open_by_url(url)
    worksheet = workbook.worksheet(sheet_title)
    return worksheet.get_all_records()

def bold(text):
    return f"*{text}*"

def format_list(list_to_print, title):
    """Format the list with an underlined title, so we get consistent formatting"""
    formatted_list = bold(title) + '\n'

    if not list_to_print:
        formatted_list = formatted_list + '🎉🎉🎉 Nothing\n'
    else:
        for record in sorted(list_to_print):
            formatted_list = formatted_list + record + '\n'
    formatted_list = formatted_list + '\n'

    return formatted_list

domain_verification_cname_pattern = re.compile('^_[0-9a-f]{32}\\.')

# Open by url sheet from a spreadsheet in one go
route53_export_url="https://docs.google.com/spreadsheets/d/197u2GPYJBZUViYF8vsXOEimHF2JL7Vi9owwBlroBYaA"
dns_records = load_google_sheet(route53_export_url)

# Massage the domain names so they're human-friendly
for record in dns_records:
    # DNS records from Route53 end with a dot, that's not helpful here.
    record['Name'] = record['Name'].rstrip('.').lower()

# Process the dns records
ns_domains = []
ignored_records = []
included_records = []
for record in dns_records:

    # Ignore if it's not a CNAME or A records
    if record['Type'] == 'NS':
        ns_domains.append(record['Name'])
    elif record['Type'] != 'CNAME' and record['Type'] != 'A':
        ignored_records.append(record)
    # Ignore if it includes domainkey
    elif 'domainkey' in record['Name']:
        ignored_records.append(record)
    # Ignore if it's a wildcard record, because we can't do anything with it:
    elif '*.' in record['Name']:
        ignored_records.append(record)
    # Ignore if it's a load of random characters
    elif domain_verification_cname_pattern.match(record['Name']):
        ignored_records.append(record)
    # Ignore records we _know_ we don't want to scan because they're email services
    elif record['Name'] == 'em6144.hackney.gov.uk' or record['Name'] == 'email.lb.hackney.gov.uk':
        ignored_records.append(record)
    else:
        included_records.append(record)

# Compare the actual DNS records with what we've got in the attack surface sheet


# Load the attack surface sheet and grab the list of domain names
attack_surface_url = "https://docs.google.com/spreadsheets/d/1KbUY_k5D_xbz633XalWwKcIT9_vV4ysMT7mIN5EECj0"
attack_surface_records = load_google_sheet(attack_surface_url, sheet_title="Current Attack Surface")

# Compare that with the DNS list
route53_domains = [record['Name'] for record in included_records]

attack_surface_domains = []
non_hackney_domains = []
for record in attack_surface_records:
    domain_name = record['Hostname/URL/IP Address'].lower()
    
    # Strip HTTP/S protocol as we just want the domain name
    domain_name = re.sub("https?://","", domain_name)

    # Strip any trailing URL pieces - anything from the first / or ? in the URL
    domain_name = re.sub("[/?)].*","", domain_name)

    # Ignore blogs becuase it's a different name server
    if domain_name.endswith('.blogs.hackney.gov.uk'):
        pass
    # Only add to our list if it's a Hackney domain
    elif 'hackney.gov.uk' in domain_name:
        attack_surface_domains.append(domain_name)
    else:
        non_hackney_domains.append(domain_name)

domains_to_add = set(route53_domains).difference(set(attack_surface_domains))

domains_to_remove = set(attack_surface_domains).difference(set(route53_domains))
domains_to_remove = [domain for domain in domains_to_remove if domain not in ns_domains]

script_repo_url = "https://github.com/LBHackney-IT/security-attack-surface-updater"

slack_blocks = [{
                  "type": "header",
                  "text": {
                      "type": "plain_text",
                      "text": "📣 Potential attack surface changes 📣"
                  }
              }, {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"The attack surface has been checked against Route53 with <{script_repo_url}|this script>"
                }
            }]


if domains_to_add:
    slack_blocks.append({
            "type": "section",
			"text": {
                "type": "mrkdwn",
                "text": f"To be added to the <{attack_surface_url}|attack surface>:\n\n{'\n'.join(['• ' + domain + '\n' for domain in domains_to_add])}"
            }
        })

if domains_to_remove:
    slack_blocks.append({
            "type": "section",
			"text": {
                "type": "mrkdwn",
                "text": f"Things we might want to REMOVE from the <{attack_surface_url}|attack surface> (check these aren't nameservers):\n\n{'\n'.join(['• ' + domain + '\n' for domain in domains_to_remove])}"
            }
        })

# 
# Uncomment this is you want to see the non-hackney domain list
#
# print(format_list(non_hackney_domains, title='Non-Hackney domain names. Check these:'))


# Only post to Slack if we have some changes to report (to keep the noise down)
if domains_to_add or domains_to_remove:
    webhook = WebhookClient(os.environ['SLACK_WEBHOOK_URL'])
    response = webhook.send(
        text="fallback",
        blocks=slack_blocks
    )
else:
    print("Nothing to report, well done!")
