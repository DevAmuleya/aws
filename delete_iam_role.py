import os
import boto3
import botocore
import logging
import json

role_name_1="KB-AuditFramework-TaskExecutionRole"
role_name_2="KB-AuditFramework-ContainerScan-Role"
role_name_3="KB-AuditFramework-TaskRole"
aws_service = "iam"
account_num = ""
target_region="us-east-1"
logger = logging.getLogger()
policy_name_1='KB-AuditFramework-CloudWatch-Access'
policy_name_2="KB-AuditFramework-ContainerScan-AssumeRole-Policy"
policy_name_3="KB-AuditFramework-ContainerScan-Logging-Policy"
policy_name_4="KB-AuditFramework-ServiceCatalog-Access"
policy_name_5="KB-AuditFramework-ECS-Access"
policy_name_6="KB-AuditFramework-S3-Access"
policy_name_7="KB-AuditFramework-SSM-Access"
policy_name_8="KB-AuditFramework-SecurityHub-Access"
policy_name_9="KB-AuditFramework-AssumeRole-To-SecretsManager-ReadRole"
policy_name_10="KB-AuditFramework-Publish-To-SNSTopic"

aws_manage_policy_1="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
aws_manage_policy_2="arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess"
aws_manage_policy_3="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
aws_manage_policy_4="arn:aws:iam::aws:policy/SecurityAudit"
aws_manage_policy_5="arn:aws:iam::aws:policy/ReadOnlyAccess"

def lambda_handler(event, context):

    try:


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


    except botocore.exceptions.ClientError as error:
        # Section for how to deal with error exceptions that might occur
        print(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish (
            TopicArn = f"arn:aws:sns:us-east-1:{account_num}:KB_Send_Failure_Notification_Topic",
            Message= f"An error has occurred during the implementation process of account {account_num}. The error is: {error_message}",
            Subject= f"Error occurred in running implementation of {aws_service} on account {account_num}."
            )
        # TO-DO: send an SNS message about the error
        raise


    try:
        detach_AWS_managed_role_policy(role_name_1,aws_manage_policy_1)
        
    except botocore.exceptions.ClientError as error:           
        return (f"policy {aws_manage_policy_1} is not attached to {role_name_1}")
        
        
    try: 
        detach_AWS_managed_role_policy(role_name_2,aws_manage_policy_2)
        
    except botocore.exceptions.ClientError as error:           
        return (f"policy {aws_manage_policy_2} is not attached to {role_name_2}")
        
    
    try: 
        detach_AWS_managed_role_policy(role_name_2,aws_manage_policy_3)
        
    except botocore.exceptions.ClientError as error:           
        return (f"policy {aws_manage_policy_3} is not attached to {role_name_2}")
        
        raise
    
    try: 
        detach_AWS_managed_role_policy(role_name_3,aws_manage_policy_4)
        
    except botocore.exceptions.ClientError as error:           
        return (f"policy {aws_manage_policy_4} is not attached to {role_name_3}")

    try: 
        detach_AWS_managed_role_policy(role_name_3,aws_manage_policy_5)
        
    except botocore.exceptions.ClientError as error:           
        return (f"policy {aws_manage_policy_5} is not attached to {role_name_3}")
                              
    try: 
       detach_role_policy(role_name_1,policy_name_1)
        
       try:
          delete__policy(policy_name_1)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_1} is not attached to another role apart from {role_name_1}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_1} is not attached to {role_name_1}")
        
    try: 
       detach_role_policy(role_name_2,policy_name_2)
       try:
          delete__policy(policy_name_2)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_2} is not attached to another role apart from {role_name_2}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_2} is not attached to {role_name_2}")
        
    try: 
       detach_role_policy(role_name_2,policy_name_3)
       try:
          delete__policy(policy_name_3)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_3} is not attached to another role apart from {role_name_2}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_3} is not attached to {role_name_2}")  
    try: 
       detach_role_policy(role_name_3,policy_name_4)
       try:
          delete__policy(policy_name_4)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_4} is not attached to another role apart from {role_name_3}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_4} is not attached to {role_name_3}")        
 
    try: 
       detach_role_policy(role_name_3,policy_name_5)
       try:
          delete__policy(policy_name_5)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_5} is not attached to another role apart from {role_name_3}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_5} is not attached to {role_name_3}")        

    try: 
       detach_role_policy(role_name_3,policy_name_6)
       try:
          delete__policy(policy_name_6)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_6} is not attached to another role apart from {role_name_3}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_6} is not attached to {role_name_3}")        
    try: 
       detach_role_policy(role_name_3,policy_name_7)
       try:
          delete__policy(policy_name_7)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_7} is not attached to another role apart from {role_name_3}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_7} is not attached to {role_name_3}")        
    
    try: 
       detach_role_policy(role_name_3,policy_name_8)
       try:
          delete__policy(policy_name_8)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_8} is not attached to another role apart from {role_name_3}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_8} is not attached to {role_name_3}")    
        
    try: 
       detach_role_policy(role_name_3,policy_name_9)
       try:
          delete__policy(policy_name_9)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_9} is not attached to another role apart from {role_name_3}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_9} is not attached to {role_name_3}")  
        
    try: 
       detach_role_policy(role_name_3,policy_name_10)
       try:
          delete__policy(policy_name_10)
       except botocore.exceptions.ClientError as error:
           
          return (f"policy {policy_name_10} is not attached to another role apart from {role_name_3}")
           
    except botocore.exceptions.ClientError as error:           
        return (f"policy {policy_name_10} is not attached to {role_name_3}")        
       

    try: 
        delete_role(role_name_1)

    except botocore.exceptions.ClientError as error:           
        return (f"policies are either still attached or  {role_name_1} does not exist")        
 
 
    try: 
        delete_role(role_name_2)

    except botocore.exceptions.ClientError as error:           
        return (f"policies are either still attached or  {role_name_2} does not exist")        
 

    try: 
        delete_role(role_name_3)

    except botocore.exceptions.ClientError as error:           
        return (f"policies are either still attached or  {role_name_3} does not exist")  
    
    res = {
        "accountData": {
            "accountId": account_num
        },
        "deleteData": {
            "service": aws_service
        },
        "status": f"{role_name_1},{role_name_2},{role_name_3} have successfully been deleted" 
    }

    return res        

            
def detach_role_policy(role_name,policy_name):
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
    
    response= sts_client.detach_role_policy(
    RoleName=role_name,
    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name}"
      )
def delete__policy(policy_name):

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
                              
    response= sts_client.delete_policy(
            PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name}"
        ) 
def delete_role(role_name):
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
    
    response_= sts_client.delete_role(
        RoleName=role_name
    )  
def detach_AWS_managed_role_policy(role_name,policy_arn):
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
    
    response= sts_client.detach_role_policy(
    RoleName=role_name,
    PolicyArn=policy_arn
   )

            