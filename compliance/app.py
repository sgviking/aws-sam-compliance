import json
import boto3
import os
from datetime import datetime
from compliance import get_access_token, get_lw_subaccounts, get_csp_accounts, summary, get_reports


def save_data(account, data, type=''):
    bucket = os.environ['BUCKET_NAME']
    filename = account + '-' + datetime.utcnow().isoformat() + f'{type}.json'
    s3 = boto3.client('s3')
    try:
        print('Saving {filename} to S3 bucket {bucket}')
        s3.put_object(Bucket=bucket, Key=filename, Body=json.dumps(data))
    except:
        raise Exception(f'Failed to create {filename} object in {bucket}')


def lambda_handler(event, context):
    account, token = get_access_token()
    subaccounts = get_lw_subaccounts(account, token)
    reports = {}
    for subaccount in subaccounts[0]['accounts']:
        reports[subaccount['accountName']] =  {'aws': {}, 'gcp': {}, 'azure': {}}
        accounts = get_csp_accounts(account, token, subaccount['accountName'])
        for aws_account in accounts['AwsCfg']:
            r = get_reports(account, subaccount['accountName'], token, 'AWS_CIS_14', aws_account)
            reports[subaccount['accountName']]['aws'][aws_account] = r
        for gcp_account in accounts['GcpCfg']:
            r  = get_reports(account, subaccount['accountName'], token, 'GCP_CIS13', gcp_account['org_id'], gcp_account['project_id'])
            reports[subaccount['accountName']]['gcp'][gcp_account['org_id'] + '/' + gcp_account['project_id']] = r
        for azure_account in accounts['AzureCfg']:
            r = get_reports(account, subaccount['accountName'], token, 'AZURE_CIS_1_5', azure_account['tenant_id'], azure_account['subscription_id'])
            reports[subaccount['accountName']]['azure'][azure_account['tenant_id'] + '/' + azure_account['subscription_id']] = r
    save_data(account, reports, '-raw')
    output = summary(reports)
    json_output = {'account': account, 'summary': output}
    save_data(account, json_output, '-summary')

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "compliance stats generated",
            "data": json.dumps(output)
        }),
    }
