# import tkinter as tk
import boto3
import botocore
import time
from datetime import datetime
import json

# root = tk.Tk()
# root.mainloop()

AWS_REGION = 'eu-west-1'
# VPC_ID = 'vpc-05a63425b4ac937e4' # eu-central
VPC_ID = 'vpc-81cf74f8'  # eu-west-1
PROTOCOL_NAME = 'Wireguard'
WG_PORT = '51820' # create check for 49152-65530
SUBNET_CHOICE = 0
CREATION_TIMEOUT_MINS = 4 
PEER_NAME = 'pablo'

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

# vpc_cidr_block = client.describe_vpcs(VpcIds=[VPC_ID])['Vpcs'][0]['CidrBlock']
# used_octets = vpc_cidr_block.split('.')[0] + '.' + vpc_cidr_block.split('.')[1]
# peer_private_ips = used_octets + '.69.0/24'

# with open('wg_create_peer.sh', 'r') as peer_script:
#     wg_create_peer = peer_script.read()
#     wg_create_peer = wg_create_peer.replace('*peer_name*', PEER_NAME)
#     wg_create_peer = wg_create_peer.replace('*port*', WG_PORT)
#     wg_create_peer = wg_create_peer.replace(
#         '*peer_private_ips*', peer_private_ips)


def get_public_subnets():
    public_subnets = []
    list_route_tables_apicall = client.describe_route_tables(
        Filters=[
            {   
                'Name': 'vpc-id',
                'Values': [VPC_ID],
            },
            {
                'Name': 'route.state',
                'Values': ['active'],
            },
            {
                'Name': 'route.destination-cidr-block',
                'Values': ['0.0.0.0/0']
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
                'Values': [VPC_ID],
            },
            {
                'Name': 'group-name',
                'Values': [f'Managed {PROTOCOL_NAME} SG'],
            },
            {
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


def get_instance_id(SUBNET_CHOICE, subnet_list):
    check_instances_apicall = client.describe_instances(
        Filters=[
            {
                'Name': 'subnet-id',
                'Values': [subnet_list[SUBNET_CHOICE]]
            },
            {
                'Name': 'instance-state-name',
                'Values': ['pending','running','stopping','stopped'],
            },
            {
                'Name': 'tag:Name',
                'Values': [f'{PROTOCOL_NAME} VPN server']
            },
            {
                'Name': 'tag:CreatedByScript',
                'Values': ['True']
            },
            {
                'Name': 'tag:Protocol',
                'Values': [f'{PROTOCOL_NAME}']
            }
        ],
    )
    instance_id = check_instances_apicall['Reservations']
    return instance_id


def create_role():
    iam_client = boto3.client('iam')
    try:
        role_check_apicall = iam_client.get_role(RoleName='EC2SSMrole')
        print('Role already exists.')
    except Exception as e:
        print(e)
        print('Creating role...')
        assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        })
        create_role_apicall = iam_client.create_role(
            RoleName='EC2SSMrole',
            AssumeRolePolicyDocument=assume_role_policy_document,
            Description='For script execution my SSM.'
        )
        attach_policy_apicall = iam_client.attach_role_policy(
            RoleName='EC2SSMrole',
            PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
        )


def get_profile_name_arn():
    iam_client = boto3.client('iam')
    try:
        profile_check_apicall = iam_client.get_instance_profile(InstanceProfileName='EC2SSMprofile')
        print('Instance profile already exists.')
    except Exception as e:
        print(e)
        print('Creating profile and attaching role to it...')
        create_profile_apicall = iam_client.create_instance_profile(InstanceProfileName='EC2SSMprofile')
        add_role_profile_apicall = iam_client.add_role_to_instance_profile(InstanceProfileName='EC2SSMprofile', RoleName='EC2SSMrole')
        profile_check_apicall = iam_client.get_instance_profile(InstanceProfileName='EC2SSMprofile')

    return profile_check_apicall
    

def create_ec2_instance_main():
    subnet_list = get_public_subnets()
    instance_id = get_instance_id(SUBNET_CHOICE, subnet_list)

    if instance_id:
        print(f'{PROTOCOL_NAME} VPN server already exists in subnet {subnet_list[SUBNET_CHOICE]}.')
        print(f'InstanceId is {instance_id[0]["Instances"][0]["InstanceId"]}, public IP {instance_id[0]["Instances"][0]["PublicIpAddress"]}')
    else:
        print(f'No {PROTOCOL_NAME} VPN server found in subnet {subnet_list[SUBNET_CHOICE]}, creating one...') 
        
        image_id = get_ami()
        security_group_id = configure_security_groups()
        create_role()
        ec2_profile = get_profile_name_arn()

        key_name = 'vpn_ssh_' + str(datetime.now().strftime('%Y%m%d%H%M%S'))
        keypair_apicall = client.create_key_pair(KeyName=key_name, KeyType='rsa')
        with open(key_name, 'w') as file:
            file.write(keypair_apicall['KeyMaterial'])
        print('Change flie permissions to 600.')

        with open('wg_install.sh', 'r') as install_script:
            wg_install = install_script.read()
            wg_install = wg_install.replace('*port*', WG_PORT)

        print(ec2_profile['InstanceProfile']['Arn'])

        time.sleep(10) # Window for API calls to settle
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
                KeyName=key_name,
                # DryRun=True,
                MaxCount=1,
                MinCount=1,
                IamInstanceProfile={
                    'Arn': ec2_profile['InstanceProfile']['Arn'],
                },
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
                        # 'PrivateIpAddress': vpn_instance_private_ip,
                        'SubnetId': subnet_list[SUBNET_CHOICE],
                        'InterfaceType': 'interface',
                    },
                ],
                UserData=wg_install,
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
        
        instance_id = get_instance_id(SUBNET_CHOICE, subnet_list)
        timeout_check = 0 # 4 minutes creation timeout
        while True:
            get_status_apicall = client.describe_instance_status(
                InstanceIds=[instance_id[0]['Instances'][0]['InstanceId']],
                Filters=[
                    {
                        'Name': 'instance-state-name',
                        'Values': ['running']
                    },
                    {
                        'Name': 'instance-status.status',
                        'Values': ['ok']
                    },
                    {
                        'Name': 'system-status.status',
                        'Values': ['ok']
                    },
                ],
            )
            if get_status_apicall['InstanceStatuses']:
                print('Instance is ready.')
                instance_id = get_instance_id(SUBNET_CHOICE, subnet_list)
                print(f'InstanceId is {instance_id[0]["Instances"][0]["InstanceId"]}, public IP {instance_id[0]["Instances"][0]["PublicIpAddress"]}')
                break
            elif timeout_check == CREATION_TIMEOUT_MINS * 6:
                print(f'Instance creation exceeded {CREATION_TIMEOUT_MINS} minutes. Stopping...')
                break
            else: 
                print('Instance still being created...')
                time.sleep(10)
                timeout_check += 1


create_ec2_instance_main()


def create_peer():
    ssm_client = boto3.client('ssm', config=Config)  # Need your credentials here
    subnet_list = get_public_subnets()
    instance_id = get_instance_id(SUBNET_CHOICE, subnet_list)[0]['Instances'][0]['InstanceId']
    
    if instance_id:
        vpc_cidr_block = client.describe_vpcs(VpcIds=[VPC_ID])['Vpcs'][0]['CidrBlock']
        used_octets = vpc_cidr_block.split('.')[0] + '.' + vpc_cidr_block.split('.')[1]
        peer_private_ips = used_octets + '.69.0/24'
        with open('wg_create_peer.sh', 'r') as peer_script:
            wg_create_peer = peer_script.read()
            wg_create_peer = wg_create_peer.replace('*peer_name*', PEER_NAME)
            wg_create_peer = wg_create_peer.replace('*port*', WG_PORT)
            wg_create_peer = wg_create_peer.replace('*peer_private_ips*', peer_private_ips)

        exec_script = ssm_client.send_command(
            DocumentName="AWS-RunShellScript",  # One of AWS' preconfigured documents
            Parameters={'commands': [wg_create_peer]},
            InstanceIds=[instance_id]
        )

        time.sleep(5)  # Avoid immeditate retrival
        command_id = exec_script['Command']['CommandId']
        output = ssm_client.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id
        )
        return output['StandardOutputContent']
    else:
        print('No WG instances found. Please, create one.')


print(create_peer())