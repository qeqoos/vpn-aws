# import tkinter as tk
import boto3
import botocore
import sys

# root = tk.Tk()
# root.mainloop()

AWS_REGION = "eu-central-1"
# VPC_ID = "vpc-05a63425b4ac937e4" # eu-central
VPC_ID = "vpc-81cf74f8"  # eu-west-1

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
vpc = ec2.Vpc(id=VPC_ID)

def get_public_subnets():
    public_subnets = []
    apicall = client.describe_route_tables()
    for routeTable in apicall['RouteTables']:
        associations = routeTable['Associations']
        routes = routeTable['Routes']
        isPublic = False
        for route in routes:
            gateway_id = route.get('GatewayId')
            if gateway_id.startswith('igw-'):
                isPublic = True
        if(not isPublic):
            continue
        for assoc in associations:
            # This checks for explicit associations, only
            subnetId = assoc.get('SubnetId')
            if subnetId:
                public_subnets.append(subnetId)
    if public_subnets:
        return public_subnets

print(get_public_subnets())