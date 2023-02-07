import os
import boto3
import botocore
import logging
import json

role_name="KB-AuditFramework-TaskExecutionRole"
role_name_1="KB-AuditFramework-ContainerScan-Role"
role_name_2="KB-AuditFramework-TaskRole"
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
        try:
            response = sts_client.get_role(
                RoleName=role_name
        ) 
            if  len(response["Role"]) > 0:
                policy_document_1={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "logs:CreateLogGroup"
                            ],
                            "Resource": "*"
                        }]}
                        
                template_policy =json.dumps(policy_document_1)
                template_policy = str(template_policy)
                try:
                    response = sts_client.create_policy(
                    PolicyName=policy_name_1,
                    PolicyDocument=template_policy,
                    Description='string'
                )
                    response =sts_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy")                 
                    response2 =sts_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_1}")
                    
                except botocore.exceptions.ClientError as error:
                    response =sts_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy") 
                                        
                    response2 =sts_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_1}")
                    
                
        except botocore.exceptions.ClientError as error:
            json_file=  {
            "Version": "2012-10-17",
            "Statement": [
                {
                "Effect": "Allow",
                "Principal": {
                    "Service": "ecs-tasks.amazonaws.com"

                },
                "Action": "sts:AssumeRole",
                "Condition": {}
                }
            ]
            }
                
            template = json.dumps(json_file)
            template = str(template)
            
            policy_document_1={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup"
                        ],
                        "Resource": "*"
                    }]}
                    
            template_policy =json.dumps(policy_document_1)
            template_policy = str(template_policy)
            
            try:
                response = sts_client.create_policy(
                PolicyName=policy_name_1,
                PolicyDocument=template_policy,
                Description='string'
            )

                role = sts_client.create_role(
                            RoleName =role_name,
                            AssumeRolePolicyDocument = template
                    )
                response =sts_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy") 
                response2 =sts_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_1}") 
                
            except botocore.exceptions.ClientError as error:
                    role = sts_client.create_role(
                                RoleName =role_name,
                                AssumeRolePolicyDocument = template
                        )
                    response =sts_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy")
                    response2 =sts_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_1}")                  

        try:
            response = sts_client.get_role(
                RoleName=role_name_1
        ) 
            if  len(response["Role"]) > 0:
                policy_document_2={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "sts:AssumeRole"
                                ],
                                "Resource": "arn:aws:iam::*:role/KB-AuditFramework-ContainerScan-AssumeRole"
                            }
                        ]
                    }
                        
                template_policy_2 =json.dumps(policy_document_2)
                template_policy_2 = str(template_policy_2)

                policy_document_3={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "kinesis:PutRecord"
                                ],
                                "Resource": f"arn:aws:kinesis:*:{account_num}:stream/kb-*"
                            }
                        ]
                    }
                        
                template_policy_3 =json.dumps(policy_document_3)
                template_policy_3 = str(template_policy_3)            
                try:
                    response = sts_client.create_policy(
                    PolicyName=policy_name_2,
                    PolicyDocument=template_policy_2,
                    Description='string'
                )
                    response = sts_client.create_policy(
                    PolicyName=policy_name_3,
                    PolicyDocument=template_policy_3,
                    Description='string'
                )            
                    response =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess")
                                    
                    response2 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_2}")
                    response3 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly")
                    response4 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_3}")

                    
                    
                except botocore.exceptions.ClientError as error:
                    response =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess")
                                    
                    response2 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_2}")
                    response3 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly") 
                    response4 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_3}")                                   
                                
        except botocore.exceptions.ClientError as error:
            json_file_1=  {
            "Version": "2012-10-17",
            "Statement": [
                {
                "Effect": "Allow",
                "Principal": {
                    "Service": "ec2.amazonaws.com"

                },
                "Action": "sts:AssumeRole",
                "Condition": {}
                }
            ]
            }
                
            template_1 = json.dumps(json_file_1)
            template_1 = str(template_1)
            
            policy_document_2={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "sts:AssumeRole"
                            ],
                            "Resource": "arn:aws:iam::*:role/KB-AuditFramework-ContainerScan-AssumeRole"
                        }
                    ]
                }
                    
            template_policy_2 =json.dumps(policy_document_2)
            template_policy_2 = str(template_policy_2)

            policy_document_3={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "kinesis:PutRecord"
                            ],
                            "Resource": f"arn:aws:kinesis:*:{account_num}:stream/kb-*"
                        }
                    ]
                }
                    
            template_policy_3 =json.dumps(policy_document_3)
            template_policy_3 = str(template_policy_3)  
            try:
                response = sts_client.create_policy(
                PolicyName=policy_name_2,
                PolicyDocument=template_policy_2,
                Description='string'
            )
                response = sts_client.create_policy(
                PolicyName=policy_name_3,
                PolicyDocument=template_policy_3,
                Description='string'
            )        
                role = sts_client.create_role(
                            RoleName =role_name_1,
                            AssumeRolePolicyDocument = template_1 
                    )            
                response =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess")
                                    
                response2 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_2}")
                response3 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly")
                response4 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_3}")                                  
                    
                    
            except botocore.exceptions.ClientError as error:
                role = sts_client.create_role(
                            RoleName =role_name_1,
                            AssumeRolePolicyDocument = template_1 
                    )            
                response =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonSSMReadOnlyAccess")
                                    
                response2 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_2}")
                response3 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn="arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly")
                response4 =sts_client.attach_role_policy(
                    RoleName=role_name_1,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_3}")                    

        try:
            response = sts_client.get_role(
                RoleName=role_name_2
        ) 
            if  len(response["Role"]) > 0:
                policy_document_4={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "servicecatalog:*"
                                ],
                                "Resource": "*",
                                "Condition": {
                                    "StringEquals": {
                                        "servicecatalog:roleLevel": "self"
                                    }
                                }
                            }
                        ]
                    }
                        
                template_policy_4 =json.dumps(policy_document_4)
                template_policy_4 = str(template_policy_4)

                policy_document_5= {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ecs:RunTask",
                                    "ecs:RegisterTaskDefinition",
                                    "ecs:DescribeTaskDefinition"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "iam:PassRole"
                                ],
                                "Resource": [
                                    "arn:aws:iam::*:role/KB-AuditFramework-TaskRole",
                                    "arn:aws:iam::*:role/KB-AuditFramework-TaskExecutionRole"
                                ],
                                "Condition": {
                                    "StringLike": {
                                        "iam:PassedToService": "ecs-tasks.amazonaws.com"
                                    }
                                }
                            }
                        ]
                    }
                        
                template_policy_5 =json.dumps(policy_document_5)
                template_policy_5 = str(template_policy_5)   
        
                policy_document_6=  {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject"
                                ],
                                "Resource": "arn:aws:s3:::KbAuditAccountParamBuckets"
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:PutObject",
                                    "s3:PutObjectAcl"
                                ],
                                "Resource": "arn:aws:s3:::KbAuditAccountResultsBuckets" 
                            }
                        ]
                    }
                        
                template_policy_6 =json.dumps(policy_document_6)
                template_policy_6 = str(template_policy_6)

                policy_document_7=  {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ssm:PutParameter",
                                    "ssm:Get*",
                                    "ssm:DeleteParameter"
                                ],
                                "Resource": f"arn:aws:ssm:*:{account_num}:parameter/CirrusScan/*"
                                
                            }
                        ]
                    }
                        
                template_policy_7 =json.dumps(policy_document_7)
                template_policy_7 = str(template_policy_7)            

                policy_document_8= {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "securityhub:BatchImportFindings",
                                    "securityhub:BatchUpdateFindings"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                        
                template_policy_8 =json.dumps(policy_document_8)
                template_policy_8 = str(template_policy_8)
                
                policy_document_9={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "sts:AssumeRole"
                                ],
                                "Resource": "arn:aws:iam::*:role/KB-AuditFramework-SecretsManagerReadOnlyRole"
                            }
                        ]
                    }
                        
                template_policy_9 =json.dumps(policy_document_9)
                template_policy_9 = str(template_policy_9)
                
                policy_document_10= {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "SNS:Publish"
                                ],
                                "Resource": f"arn:aws:sns:*:{account_num}:AuditSNSTopic"
                                
                            }
                        ]
                    }
                template_policy_10 =json.dumps(policy_document_10)
                template_policy_10 = str(template_policy_10)
                
                try:
                    response = sts_client.create_policy(
                    PolicyName=policy_name_4,
                    PolicyDocument=template_policy_4,
                    Description='string'
                )
                    response = sts_client.create_policy(
                    PolicyName=policy_name_5,
                    PolicyDocument=template_policy_5,
                    Description='string'
                )   
                    response = sts_client.create_policy(
                    PolicyName=policy_name_6,
                    PolicyDocument=template_policy_6,
                    Description='string'
                )   
                    response = sts_client.create_policy(
                    PolicyName=policy_name_7,
                    PolicyDocument=template_policy_7,
                    Description='string'
                )   
                    response = sts_client.create_policy(
                    PolicyName=policy_name_8,
                    PolicyDocument=template_policy_8,
                    Description='string'
                )   
                    response = sts_client.create_policy(
                    PolicyName=policy_name_9,
                    PolicyDocument=template_policy_9,
                    Description='string'
                )   
                    response = sts_client.create_policy(
                    PolicyName=policy_name_10,
                    PolicyDocument=template_policy_10,
                    Description='string'
                )   

                    response =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn="arn:aws:iam::aws:policy/SecurityAudit")
                                    
                    response2 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_4}")
                    response3 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
                    response4 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_5}")
                    response5 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_6}")
                    response6 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_7}")
                    response7 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_8}")
                    response8 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_9}") 
                    response9 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_10}")
                    
                    
                    
                except botocore.exceptions.ClientError as error:
                    response =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn="arn:aws:iam::aws:policy/SecurityAudit")
                                    
                    response2 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_4}")
                    response3 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
                    response4 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_5}")
                    response5 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_6}")
                    response6 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_7}")
                    response7 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_8}")
                    response8 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_9}") 
                    response9 =sts_client.attach_role_policy(
                    RoleName=role_name_2,
                    PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_10}")
                    
                                                    
                                
        except botocore.exceptions.ClientError as error:
            json_file_2=  {
            "Version": "2012-10-17",
            "Statement": [
                {
                "Effect": "Allow",
                "Principal": {
                    "Service": "ec2.amazonaws.com"

                },
                "Action": "sts:AssumeRole",
                "Condition": {}
                }
            ]
            }
                
            template_2 = json.dumps(json_file_2)
            template_2 = str(template_2)
            
            policy_document_4={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "servicecatalog:*"
                            ],
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {
                                    "servicecatalog:roleLevel": "self"
                                }
                            }
                        }
                    ]
                }
                    
            template_policy_4 =json.dumps(policy_document_4)
            template_policy_4 = str(template_policy_4)

            policy_document_5= {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "ecs:RunTask",
                                "ecs:RegisterTaskDefinition",
                                "ecs:DescribeTaskDefinition"
                            ],
                            "Resource": "*"
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "iam:PassRole"
                            ],
                            "Resource": [
                                "arn:aws:iam::*:role/KB-AuditFramework-TaskRole",
                                "arn:aws:iam::*:role/KB-AuditFramework-TaskExecutionRole"
                            ],
                            "Condition": {
                                "StringLike": {
                                    "iam:PassedToService": "ecs-tasks.amazonaws.com"
                                }
                            }
                        }
                    ]
                }
                    
            template_policy_5 =json.dumps(policy_document_5)
            template_policy_5 = str(template_policy_5)   
    
            policy_document_6=  {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:GetObject"
                                ],
                                "Resource": "arn:aws:s3:::KbAuditAccountParamBuckets"
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "s3:PutObject",
                                    "s3:PutObjectAcl"
                                ],
                                "Resource": "arn:aws:s3:::KbAuditAccountResultsBuckets" 
                            }
                        ]
                    }
                    
            template_policy_6 =json.dumps(policy_document_6)
            template_policy_6 = str(template_policy_6)

            policy_document_7=  {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "ssm:PutParameter",
                                "ssm:Get*",
                                "ssm:DeleteParameter"
                            ],
                            "Resource": f"arn:aws:ssm:*:{account_num}:parameter/CirrusScan/*"
                            
                        }
                    ]
                }
                    
            template_policy_7 =json.dumps(policy_document_7)
            template_policy_7 = str(template_policy_7)            

            policy_document_8= {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "securityhub:BatchImportFindings",
                                "securityhub:BatchUpdateFindings"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
                    
            template_policy_8 =json.dumps(policy_document_8)
            template_policy_8 = str(template_policy_8)
            
            policy_document_9={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "sts:AssumeRole"
                            ],
                            "Resource": "arn:aws:iam::*:role/KB-AuditFramework-SecretsManagerReadOnlyRole"
                        }
                    ]
                }
                    
            template_policy_9 =json.dumps(policy_document_9)
            template_policy_9 = str(template_policy_9)
            
            policy_document_10= {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "SNS:Publish"
                            ],
                            "Resource": f"arn:aws:sns:*:{account_num}:AuditSNSTopic"
                            
                        }
                    ]
                }
            template_policy_10 =json.dumps(policy_document_10)
            template_policy_10 = str(template_policy_10)
            
            try:
                response = sts_client.create_policy(
                PolicyName=policy_name_4,
                PolicyDocument=template_policy_4,
                Description='string'
            )
                response = sts_client.create_policy(
                PolicyName=policy_name_5,
                PolicyDocument=template_policy_5,
                Description='string'
            )   
                response = sts_client.create_policy(
                PolicyName=policy_name_6,
                PolicyDocument=template_policy_6,
                Description='string'
            )   
                response = sts_client.create_policy(
                PolicyName=policy_name_7,
                PolicyDocument=template_policy_7,
                Description='string'
            )   
                response = sts_client.create_policy(
                PolicyName=policy_name_8,
                PolicyDocument=template_policy_8,
                Description='string'
            )   
                response = sts_client.create_policy(
                PolicyName=policy_name_9,
                PolicyDocument=template_policy_9,
                Description='string'
            )   
                response = sts_client.create_policy(
                PolicyName=policy_name_10,
                PolicyDocument=template_policy_10,
                Description='string'
            )   
                role = sts_client.create_role(
                            RoleName =role_name_2,
                            AssumeRolePolicyDocument = template_2 
                    )
                response =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn="arn:aws:iam::aws:policy/SecurityAudit")
                                
                response2 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_4}")
                response3 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
                response4 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_5}")
                response5 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_6}")
                response6 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_7}")
                response7 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_8}")
                response8 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_9}") 
                response9 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_10}")
                
        
                    
            except botocore.exceptions.ClientError as error:
                role = sts_client.create_role(
                            RoleName =role_name_2,
                            AssumeRolePolicyDocument = template_2 
                    )
                response =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn="arn:aws:iam::aws:policy/SecurityAudit")
                                
                response2 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_4}")
                response3 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
                response4 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_5}")
                response5 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_6}")
                response6 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_7}")
                response7 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_8}")
                response8 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_9}") 
                response9 =sts_client.attach_role_policy(
                RoleName=role_name_2,
                PolicyArn=f"arn:aws:iam::{account_num}:policy/{policy_name_10}")                  

    except botocore.exceptions.ClientError as error:
        logger.error(f"Error: {error}")
        error_message = error.response["Error"]["Message"]
        sns_client = boto3.client("sns")
        sns_client.publish (
            TopicArn = f"arn:aws:sns:us-east-1:{account_num}:KB_Send_Failure_Notification_Topic",
            Message = f"An error has occured during the scanning process of account {account_num}. The error is: {error_message}",
            Subject = f"Error occured in running scan of {aws_service} on account {account_num}."
        )
        raise            