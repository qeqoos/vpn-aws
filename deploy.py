# import tkinter as tk
import boto3
import botocore
import sys

# root = tk.Tk()
# root.mainloop()

AWS_REGION = 'eu-west-1'
# VPC_ID = 'vpc-05a63425b4ac937e4' # eu-central
VPC_ID = 'vpc-81cf74f8'  # eu-west-1
PROTOCOL_NAME = 'Wireguard'
WG_PORT = '51820' # create check for 49152-65530

Config = botocore.config.Config(region_name=AWS_REGION)

# client = boto3.client(
#     'ec2',
#     aws_access_key_id='',
#     aws_secret_access_key='',
#     config=Config
# )

client = boto3.client(
    "ec2",
    config=Config
)

ec2 = boto3.resource('ec2', region_name=AWS_REGION)

def get_public_subnets():
    public_subnets = []
    list_route_tables_apicall = client.describe_route_tables(
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
    for route_table in list_route_tables_apicall['RouteTables']:
        associations = route_table['Associations']
        for assoc in associations:
            # This checks for explicit associations, only
            subnetId = assoc.get('SubnetId')
            if subnetId:
                public_subnets.append(subnetId)
    return public_subnets if public_subnets else print(f'No public subnets in {VPC_ID}. Please, create one.')       


def configure_security_groups():
    list_sgs_apicall = client.describe_security_groups(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values': [
                        VPC_ID,
                ],
                'Name': 'group-name',
                'Values': [
                        f'Managed {PROTOCOL_NAME} SG',
                ],
                'Name': 'tag:CreatedByScript',
                'Values': ['True']
            },
        ]
    )

    if list_sgs_apicall['SecurityGroups']:
        created_sg_id = list_sgs_apicall['SecurityGroups'][0]['GroupId']
        print(f'{PROTOCOL_NAME} SG on port {WG_PORT} already exists in VPC. SG ID is {created_sg_id}')
    else: 
        print(f'No {PROTOCOL_NAME} SG found on port {WG_PORT}, creating one...')
        try:
            create_sg_apicall = client.create_security_group(
                VpcId=VPC_ID,
                GroupName=f'Managed {PROTOCOL_NAME} SG',
                Description=f'Allows {PROTOCOL_NAME} and SSH connection',
                TagSpecifications=[
                    {
                        'ResourceType': 'security-group',
                        'Tags': [
                            {
                                'Key': 'CreatedByScript',
                                'Value': 'True'
                            },
                            {
                                'Key': 'Protocol',
                                'Value': f'{PROTOCOL_NAME}'
                            }
                        ]
                    },
                ],
            )
            created_sg_id = create_sg_apicall['GroupId']
            rules_apicall = client.authorize_security_group_ingress(
                GroupId=created_sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'udp',
                        'FromPort': int(WG_PORT),
                        'ToPort': int(WG_PORT),
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ],
            )
        except Exception as e:
            print(f'Error in security group configuration - {e}')

    return created_sg_id


def get_ami():
    try:
        list_images_apicall = client.describe_images(
            Owners=['099720109477'], # Canonical
            IncludeDeprecated=False,
            Filters=[
                {
                    'Name': 'name',
                    'Values': [
                        'ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20220419',
                    ]
                },
            ]
        )
        ami = list_images_apicall['Images'][0]['ImageId']
        print('Found AMI.')
        return ami
    except IndexError:
        print('No suitable AMI found. Check filters.')
        

def create_ec2_instance_main():
    SUBNET_CHOICE = 0
    subnet_list = get_public_subnets()

    check_instances_apicall = client.describe_instances(
        Filters=[
            {
                'Name': 'subnet-id',
                'Values': [subnet_list[SUBNET_CHOICE]],
                'Name': 'tag:Name',
                'Values': [f'{PROTOCOL_NAME} VPN server'],
                'Name': 'tag:CreatedByScript',
                'Values': ['True'],
                'Name': 'tag:Protocol',
                'Values': [f'{PROTOCOL_NAME}'],
            },
        ],
    )
    if check_instances_apicall['Reservations']:
        print(
            f'{PROTOCOL_NAME} VPN server already exists in subnet {subnet_list[SUBNET_CHOICE]}.')
    else:
        print(f'No {PROTOCOL_NAME} VPN server found in subnet {subnet_list[SUBNET_CHOICE]}, creating one...') 
        image_id = get_ami()
        security_group_id = configure_security_groups()
        print('Prerequisites finshed. Started creation of server...')
        try:     
            server = ec2.create_instances(
                BlockDeviceMappings=[
                    {
                        'DeviceName': '/dev/sda1',
                        'VirtualName': 'string',
                        'Ebs': {
                            'DeleteOnTermination': True,
                            'VolumeSize': 8,
                            'VolumeType': 'gp2',
                            'Encrypted': False
                        },
                    },
                ],
                ImageId=image_id,
                InstanceType='t2.micro',
                # KeyName='string',
                # DryRun=True,
                MaxCount=1,
                MinCount=1,
                Monitoring={
                    'Enabled': False
                },
                NetworkInterfaces=[
                    {
                        'DeviceIndex': 0,
                        'AssociatePublicIpAddress': True,
                        'DeleteOnTermination': True,
                        'Groups': [
                            security_group_id,
                        ],
                        # 'PrivateIpAddress': 'string',
                        'SubnetId': subnet_list[SUBNET_CHOICE],
                        'InterfaceType': 'interface',
                    },
                ],
                # UserData='string',
                InstanceInitiatedShutdownBehavior='stop', 
                TagSpecifications=[
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {
                                'Key': 'Name',
                                'Value': f'{PROTOCOL_NAME} VPN server'
                            },
                            {
                                'Key': 'CreatedByScript',
                                'Value': 'True'
                            },
                            {
                                'Key': 'Protocol',
                                'Value': f'{PROTOCOL_NAME}'
                            }
                        ]
                    },
                ],
            )
        except Exception as e:
            print(f'Error in server configuration - {e}')

create_ec2_instance_main()
