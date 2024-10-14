import boto3
from botocore.exceptions import ClientError
import json
import logging
import os
import time

# Initialize logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] - %(message)s', force=True)

# Constants
BODY = """
<p>Hi,<br />Email: {}</p>
<p><strong><u>Your access key has been rotated. </u></strong><br />Please visit the following link to find your new access keys: {}</p>
<p>Please bear in mind that all previous access key have been revoked and will no longer work.<br />
<p>Thank you,<br />Company AWS Admin</p>
"""



# Helper function to get IAM client
def get_iam_client():
    return boto3.client('iam')

# Helper function to get Secrets Manager client
def get_secrets_client():
    return boto3.client('secretsmanager')

# Helper function to get SES client
def get_ses_client():
    return boto3.client('ses')

# Helper function to get SNS client
def get_sns_client():
    return boto3.client('sns')

# Helper function to send SNS notifications
def sns_notify(message):
    sns_client = get_sns_client()
    sns_client.publish(TopicArn=os.environ['sns_topic_arn'], Message=message)

# Error handler decorator
def error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            logging.error(f"ClientError in {func.__name__}: {e}")
            sns_notify(f"Error in {func.__name__}: {str(e)}")
            raise e
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {e}")
            sns_notify(f"Error in {func.__name__}: {str(e)}")
            raise e
    return wrapper

@error_handler
def create_key(username):
    iam_client = get_iam_client()
    access_key_metadata = iam_client.create_access_key(UserName=username)
    access_key = access_key_metadata['AccessKey']['AccessKeyId']
    secret_key = access_key_metadata['AccessKey']['SecretAccessKey']
    logging.info(f"Access key {access_key} has been created for user {username}.")
    return access_key, secret_key

@error_handler
def add_secret_version(secret_id, token, access_key, secret_key):
    secrets_client = get_secrets_client()
    secret_data = json.dumps({"access_key_id": access_key, "secret_access_key": secret_key})
    secrets_client.put_secret_value(
        SecretId=secret_id,
        ClientRequestToken=token,
        SecretString=secret_data,
        VersionStages=['AWSPENDING'] # see https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_UpdateSecretVersionStage.html
    )
    logging.info(f"Secret version added to Secrets Manager for access key {access_key}.")

@error_handler
def test_secret(secret_id, token, username):
    secrets_client = get_secrets_client()
    secret_value = secrets_client.get_secret_value(SecretId=secret_id, VersionId=token, VersionStage='AWSPENDING')
    access_key_id = json.loads(secret_value['SecretString'])['access_key_id']
    secret_access_key = json.loads(secret_value['SecretString'])['secret_access_key']

    # Test access key by listing IAM keys
    time.sleep(10)  # Wait for keys to propagate
    iam_test_client = boto3.client('iam', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key)
    iam_test_client.list_access_keys(UserName=username)
    logging.info(f"IAM test for access key {access_key_id} passed.")

@error_handler
def rotate_secret_version(secret_id, token):
    secrets_client = get_secrets_client()
    current_secret_versions = secrets_client.list_secret_version_ids(SecretId=secret_id)['Versions']
    for version in current_secret_versions:
        if version['VersionStages'][0] == 'AWSCURRENT':
            previous_secret_version = version['VersionId']
            secrets_client.update_secret_version_stage(
                SecretId=secret_id,
                VersionStage='AWSCURRENT',
                RemoveFromVersionId=previous_secret_version,
                MoveToVersionId=token
            )
            logging.info(f"Secret rotation successful for secret {secret_id}.")
            return
    logging.error("Secret rotation failed.")
    sns_notify("Error during secret rotation.")

@error_handler
def revoke_old_access_keys(secret_id, token, username):
    secrets_client = get_secrets_client()
    secret_versions = secrets_client.list_secret_version_ids(SecretId=secret_id)
    for version in secret_versions['Versions']:
        if 'AWSPREVIOUS' in version['VersionStages']:
            previous_version_id = version['VersionId']
            previous_secret_value = secrets_client.get_secret_value(SecretId=secret_id, VersionId=previous_version_id)
            old_access_key_id = json.loads(previous_secret_value['SecretString'])['access_key_id']
            if len(old_access_key_id) > 8:
                disable_key(old_access_key_id, username)
                delete_key(old_access_key_id, username)

@error_handler
def disable_key(access_key, username):
    iam_client = get_iam_client()
    iam_client.update_access_key(UserName=username, AccessKeyId=access_key, Status="Inactive")
    logging.info(f"Access key {access_key} has been disabled for user {username}.")

@error_handler
def delete_key(access_key, username):
    iam_client = get_iam_client()
    iam_client.delete_access_key(UserName=username, AccessKeyId=access_key)
    logging.info(f"Access key {access_key} has been deleted for user {username}.")

@error_handler
def send_email(username, domain):
    ses_client = get_ses_client()
    dest_address = f"{username}{domain}"
    email_body = BODY.format(dest_address, 'https://console.aws.amazon.com/secretsmanager/home')
    
    ses_client.send_email(
        Source=os.environ['source_email'],
        Destination={'ToAddresses': [dest_address]},
        Message={
            'Subject': {'Data': 'AWS Access Key Rotation', 'Charset': 'UTF-8'},
            'Body': {'Html': {'Data': email_body, 'Charset': 'UTF-8'}}
        }
    )
    logging.info(f"Email sent to {dest_address} about access key rotation.")

@error_handler
def check_current_secret(user, secret_id, secret_stage):
    secrets_client = get_secrets_client()
    iam_client = get_iam_client()

    # Retrieve the current secret
    secret = secrets_client.get_secret_value(SecretId=secret_id)
    secret_versions = secrets_client.list_secret_version_ids(SecretId=secret_id)['Versions']
    access_key_id = json.loads(secret['SecretString'])['access_key_id']
    user_keys = iam_client.list_access_keys(UserName=user)['AccessKeyMetadata']

    if secret_stage == 'createSecret':
        # Handle interrupted secrets
        if len(secret_versions) == 3:
            logging.info(f"Handling 3 secret versions for {user}")
            for version in secret_versions:
                if version['VersionStages'][0] == 'AWSPENDING':
                    pending_secret = secrets_client.get_secret_value(SecretId=secret_id, VersionStage='AWSPENDING')
                    pending_access_key = json.loads(pending_secret['SecretString'])['access_key_id']
                    for current_key in user_keys:
                        if current_key['AccessKeyId'] == pending_access_key:
                            logging.info('Access key matches pending secret; skipping createSecret step.')
                            return False
                    logging.error('Pending secret does NOT match current IAM access key.')
                    raise RuntimeError('Pending secret and IAM access key mismatch.')

        # Normal operation (2 or fewer versions)
        if len(secret_versions) <= 2:
            logging.info(f"Normal secret rotation for {user} with {len(secret_versions)} versions.")
            if len(user_keys) == 1:
                logging.info(f"User {user} has 1 access key.")
            elif len(user_keys) == 2:
                logging.info(f"User {user} has 2 access keys; removing unused key.")
                for key in user_keys:
                    if key['AccessKeyId'] != access_key_id:
                        delete_key(access_key=key['AccessKeyId'], username=user)
    return True

def lambda_handler(event, context):
    secret_id = event['SecretId']
    secret_stage = event['Step']
    token = event['ClientRequestToken']
    username = "test-key-rotator2"
    notification = "vlad.maracine"
    domain = "@yahoo.com"

    logging.info(f"Stage: {secret_stage}, username: {username}, Token: {token}")

    if check_current_secret(username, secret_id, secret_stage):
        if secret_stage == 'createSecret':
            access_key, secret_key = create_key(username)
            add_secret_version(secret_id, token, access_key, secret_key)
        elif secret_stage == 'testSecret':
            test_secret(secret_id, token, username)
        elif secret_stage == 'finishSecret':
            rotate_secret_version(secret_id, token)
            revoke_old_access_keys(secret_id, token, username)
            send_email(notification, domain)

    return {
        'statusCode': 200,
        'body': 'success'
    }
