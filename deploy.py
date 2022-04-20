# import tkinter as tk
import boto3
import botocore
import sys

# root = tk.Tk()
# root.mainloop()

AWS_REGION = "eu-central-1"
VPC_ID = "vpc-05a63425b4ac937e4" # eu-central
# VPC_ID = "vpc-81cf74f8"  # eu-west-1

Config = botocore.config.Config(region_name=AWS_REGION)

# client = boto3.client(
#     "ec2",
#     aws_access_key_id="pass",
#     aws_secret_access_key="pass",
#     config=Config
# )

client = boto3.client(
    "ec2",
    config=Config
)

ec2 = boto3.resource('ec2', region_name=AWS_REGION)

def get_public_subnets():
    public_subnets = []
    apicall = client.describe_route_tables(
        Filters=[
            {   
                'Name': 'vpc-id',
                'Values': [
                    VPC_ID,
                ],
                'Name': 'route.state',
                'Values': [
                    'active',
                ],
                'Name': 'route.destination-cidr-block',
                'Values': [
                    '0.0.0.0/0',
                ]
            },
        ]
    )
    for routeTable in apicall['RouteTables']:
        associations = routeTable['Associations']
        for assoc in associations:
            # This checks for explicit associations, only
            subnetId = assoc.get('SubnetId')
            if subnetId:
                public_subnets.append(subnetId)
    return public_subnets if public_subnets else print(f"No public subnets in {VPC_ID}")       

def configure_security_groups():
    apicall = client.describe_security_groups(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [
                        VPC_ID,
                ]
            },
        ]
    )
    print(apicall)

def create_ec2_instance():
    pass

# print(get_public_subnets())
configure_security_groups()