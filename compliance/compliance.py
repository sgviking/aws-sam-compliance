#!/usr/bin/env python3

import json
import requests
import boto3 
import os

def get_lw_subaccounts(account, token):
    """
    https://docs.lacework.net/api/v2/docs/#tag/UserProfile
    /api/v2/UserProfile
    """
    url = f'https://{account}.lacework.net/api/v2/UserProfile'
    headers = { 'Content-Type':'application/json',
                'Authorization':f'Bearer {token}',
                'Account-Name': account }
    results = requests.get(url, headers=headers)
    try:
        subaccounts = results.json().get('data')
    except:
        raise Exception(f'Could not retrieve accounts for {account}')
    return subaccounts


def get_azure_subscriptions(account, token, subaccount, tenant_id):
    """
    https://docs.lacework.net/api/v2/docs/#tag/Configs/paths/~1api~1v2~1Configs~1AzureSubscriptions/get
    /api/v2/Configs/AzureSubscriptions?tenantId={tenantId}
    """
    url = f'https://{account}.lacework.net/api/v2/Configs/AzureSubscriptions?tenantId={tenant_id}'
    headers = { 'Content-Type':'application/json',
                'Authorization':f'Bearer {token}',
                'Account-Name': subaccount }
    results = requests.get(url, headers=headers)
    accounts = []
    try:
        subscriptions = results.json().get('data', [])[0].get('subscriptions', [])
    except:
        return []
    for subscription in subscriptions:
        accounts.append({'tenant_id': tenant_id, 'subscription_id': subscription})
    return accounts 


def get_gcp_projects(account, token, subaccount, org_id):
    """
    https://docs.lacework.net/api/v2/docs/#tag/Configs/paths/~1api~1v2~1Configs~1GcpProjects/get
    /api/v2/Configs/GcpProjects?orgId={orgId}
    """
    url = f'https://{account}.lacework.net/api/v2/Configs/GcpProjects?orgId={org_id}'
    headers = { 'Content-Type':'application/json',
                'Authorization':f'Bearer {token}',
                'Account-Name': subaccount }
    results = requests.get(url, headers=headers)
    accounts = []
    try:
        projects = results.json().get('data', [])[0].get('projects', [])
    except:
        return []
    for project in projects:
        accounts.append({'org_id': org_id, 'project_id': project})
    return accounts 


def get_csp_accounts(account, token, subaccount):
    """
    https://docs.lacework.net/api/v2/docs/#tag/CloudAccounts/paths/~1api~1v2~1CloudAccounts/get
    /api/v2/CloudAccounts
    """
    url = f'https://{account}.lacework.net/api/v2/CloudAccounts'
    headers = { 'Content-Type':'application/json',
                'Authorization':f'Bearer {token}',
                'Account-Name': subaccount }
    results = requests.get(url, headers=headers)
    accounts = { 'AwsCfg': [], 'GcpCfg': [], 'AzureCfg': [] }
    try:
        csp_accounts = results.json().get('data', [])
    except:
        return accounts
    for csp_account in csp_accounts:
        if csp_account['type'] == 'AwsCfg':
            accounts['AwsCfg'].append(csp_account['data']['awsAccountId'])
        elif csp_account['type'] == 'AzureCfg':
            subscriptions = get_azure_subscriptions(account, token, subaccount, csp_account['data']['tenantId'])
            accounts['AzureCfg'] = accounts['AzureCfg'] + subscriptions
        elif csp_account['type'] == 'GcpCfg':
            projects = get_gcp_projects(account, token, subaccount, csp_account['data']['id'])
            accounts['GcpCfg'] = accounts['GcpCfg'] + projects 
    return accounts


def get_lw_api_secrets():
    """
    Reads in secrets from SecretManager name from environment variable BUCKET_NAME 
    Expected structure inside of the secret:
    - LW_ACCOUNT
    - LW_API_KEY
    - LW_API_SECRET
    """
    try:
        client = boto3.client('secretsmanager')
        lw_api = json.loads(client.get_secret_value(SecretId=os.environ['SECRETS_ARN'])['SecretString'])
    except:
        raise Exception('Failed to retrieve lacework_api from SecretsManager')
    if lw_api.get('LW_ACCOUNT') and lw_api.get('LW_API_KEY') and lw_api.get('LW_API_SECRET'):
        return lw_api
    else:
        raise Exception('lacework_api secret must contain LW_ACCOUNT, LW_API_KEY, and LW_API_SECRET')


def get_access_token():
    """
    https://docs.lacework.net/api/v2/docs/#tag/ACCESS_TOKENS
    """
    lw_api = get_lw_api_secrets()
    api_key = lw_api.get('LW_API_KEY')
    api_secret = lw_api.get('LW_API_SECRET')
    account = lw_api['LW_ACCOUNT']
    url = f'https://{account}.lacework.net/api/v2/access/tokens'
    headers = { 'Content-Type': 'application/json', 'X-LW-UAKS': api_secret }
    data = { 'keyId': api_key, 'expiryTime': 36000 }
    results = requests.post(url, headers=headers, data=json.dumps(data))
    token = results.json()['token']
    return account, token


def get_reports(account, subaccount, token, report, primary_id, secondary_id=None):
    print(f'Getting {report} report for IDs {primary_id}, {secondary_id} in sub-account {subaccount}')
    headers = { 'Content-Type':'application/json',
                'Authorization':f'Bearer {token}',
                'Account-Name': subaccount }
    url = f'https://{account}.lacework.net/api/v2/Reports?primaryQueryId={primary_id.split()[0]}&format=json&reportType={report}'
    if secondary_id:
        url = f'{url}&secondaryQueryId={secondary_id.split()[0]}'
    results = requests.get(url, headers=headers)
    try:
        return results.json()['data'][0]['summary'][0]
    except:
        print(f'Failed to retrieve report for {account} {subaccount} {report} {primary_id}')
        return {}


def summary(reports):
    output = ''
    for subaccount in reports:
        print(f'Generating summary for {subaccount}')
        csps = {'aws': 'Accounts', 'gcp': 'Projects', 'azure': 'Subscriptions'}
        output = output + f'{subaccount} -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n'
        for csp in csps:
            rcount = 0
            rfailed = 0
            rexceptions = 0
            not_compliant = 0
            compliant = 0
            highsev = 0
            count = 0

            accounts = reports[subaccount].get(csp, None)
            if not accounts:
                continue
            for account_id, report in reports[subaccount][csp].items():
                total_policies = report.get('NUM_RECOMMENDATIONS', None)
                if total_policies is None:
                    continue
                count = count + 1
                # not_compliant = not_compliant + report['NUM_NOT_COMPLIANT']
                compliant = compliant + report['NUM_COMPLIANT']
                highsev = highsev + report['NUM_SEVERITY_1_NON_COMPLIANCE'] + report['NUM_SEVERITY_2_NON_COMPLIANCE']
                rcount = rcount + report['ASSESSED_RESOURCE_COUNT']
                rfailed = rfailed + report['VIOLATED_RESOURCE_COUNT']
                rexceptions = rexceptions + report['SUPPRESSED_RESOURCE_COUNT']
                account_highsev = round((float(report['NUM_SEVERITY_1_NON_COMPLIANCE'] + report['NUM_SEVERITY_2_NON_COMPLIANCE']) / float(total_policies)) * 100, 1)
                account_compliant = round((float(report['NUM_COMPLIANT']) / total_policies) * 100, 1)
                # print(f' Compliant: {report["NUM_COMPLIANT"]} High sev non-compliant: {report["NUM_SEVERITY_1_NON_COMPLIANCE"] + report["NUM_SEVERITY_2_NON_COMPLIANCE"]} Total: {total_policies}\n')
                output = output + f' {account_id}\tCompliant: {account_compliant}%\tHigh severity: {account_highsev}%\n'
            if count < 1:
                continue

            total = total_policies * count
            percent_compliant = round((float(compliant) / float(total)) * 100, 1)
            percent_highsev = round((float(highsev) / float(total)) * 100, 1)
            # print(f' Compliant: {compliant} High sev non-compliant: {highsev} Total: {total}')
            output = output + f' {csp.upper()} {csps[csp]}: {count}\tRecommendations: {total_policies}\tResources: {rcount}\tFailed: {rfailed}\tCompliant: {percent_compliant}%\tHigh severity: {percent_highsev}%\n'
    return output