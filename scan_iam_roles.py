import os
import boto3
import botocore
import logging

logger = logging.getLogger()

def lambda_handler(event, context):
    sts = boto3.client("sts")
    log_level = os.environ.get("log_level", "INFO")
    logger.setLevel(level=log_level)
    logger.info(f"REQUEST: {event}")
    enabled_services = event["enabledServices"]    
    aws_service = "iam"
    account_data = ""
    account_num = ""
    target_region = ""
    role_name="KB-AuditFramework-TaskExecutionRole"
    role_name_1="KB-AuditFramework-ContainerScan-Role"
    role_name_2="KB-AuditFramework-TaskRole"
    try:
        #validate event and env var

        
        sts = boto3.client("sts")  
        logger.info(f"Starting scan of new account {account_num}")
        logger.info(f"account_num: {account_num}")
        role_arn = f"arn:aws:iam::{account_num}:role/KB_assumed_role"
        sts_auth = sts.assume_role(RoleArn=role_arn, RoleSessionName="acquired_account_role")
        credentials = sts_auth["Credentials"]
        
        # ----------------------------- #
        # Place all service code below
        # ----------------------------- #

        # Section for boto3 connection with aws service
        sts_client = boto3.client(aws_service,
                                  region_name=target_region,
                                  aws_access_key_id=credentials["AccessKeyId"],
                                  aws_secret_access_key=credentials["SecretAccessKey"],
                                  aws_session_token=credentials["SessionToken"], )
        try:
            response = sts_client.get_role(
                RoleName=role_name
        ) 
            try:
                response = sts_client.get_role(
                RoleName=role_name_1
        )
                try:
                    response = sts_client.get_role(
                        RoleName=role_name_2
                        
                )
                    if  len(response["Role"]) > 0:
                        status = "enabled"
                        logger.info(f"iam role {role_name} has alreeady been  created. Account Num: {account_num}")
                        response = {
                            "enabledServices": "enabled_services",
                            "accountData": account_num,
                            "scanData": {
                                "service": aws_service,
                                "role_name": [role_name,role_name_1,role_name_2],
                                "status": status
                            }
                        }
                
                        return response
                except botocore.exceptions.ClientError as error:
                    status = "disabled"
                    logger.info(f"iam role {role_name} does not exist. Account Num: {account_num}")
                    response = {
                        "enabledServices": enabled_services,
                        "accountData": account_num,
                        "scanData": {
                            "service": aws_service,
                            "status": status
                        }
                    }
                    return response

            except botocore.exceptions.ClientError as error:
                status = "disabled"
                logger.info(f"iam role {role_name} does not exist. Account Num: {account_num}")
                response = {
                    "enabledServices": enabled_services,
                    "accountData": account_num,
                    "scanData": {
                        "service": aws_service,
                        "status": status
                    }
                }
                return response


        except botocore.exceptions.ClientError as error:
            status = "disabled"
            logger.info(f"iam role {role_name} does not exist. Account Num: {account_num}")
            response = {
                "enabledServices": enabled_services,
                "accountData": account_num,
                "scanData": {
                    "service": aws_service,
                    "status": status
                }
            }
            return response
    except botocore.exceptions.ClientError as error:
        logger.error(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish (
            TopicArn = f"arn:aws:sns:us-east-1:{account_num}:GD_Send_Failure_Notification_Topic",
            Message = f"An error has occured during the scanning process of account {account_num}. The error is: {error_message}",
            Subject = f"Error occured in running scan of {aws_service} on account {account_num}."
        )
        raise       
                                