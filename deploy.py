from tkinter import *
from tkinter import ttk
from tkinter.messagebox import *

import boto3
import botocore
import time
from datetime import datetime
import json

AWS_REGION = 'eu-west-1'  # user enters
# VPC_ID = 'vpc-05a63425b4ac937e4'  # eu-central, user enters
# VPC_ID = 'vpc-81cf74f8'  # eu-west-1
VPC_ID = 'vpc-0e128b2f79b9e772d' 

SSH_PORT = ''
CREATION_TIMEOUT_MINS = 5 
PROTOCOL_NAME = 'Wireguard' # default

# WG
# PROTOCOL_NAME = 'Wireguard'
WG_PORT = ''
PEER_NAME = '' 

# IPsec
# PROTOCOL_NAME = 'IPsec'  
USERNAME = ''  
PASSWORD = ''  

Config = botocore.config.Config(region_name=AWS_REGION)

client = boto3.client(
    "ec2",
    config=Config
)

ec2 = boto3.resource('ec2', region_name=AWS_REGION)


def get_public_subnets():
    check_creds()
    public_subnets = []
    VPC_ID = vpc_id.get()
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
    if public_subnets:
        subnet_box['values'] = public_subnets
        subnet_box.current(0)
    else: 
        showwarning('Warning', f'No public subnets in {VPC_ID}. Please, create one.')       


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
        print(f'{PROTOCOL_NAME} SG already exists in VPC.')
    else: 
        print(f'No {PROTOCOL_NAME} SG found, creating one...')
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
            if PROTOCOL_NAME == 'Wireguard':
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
                            'FromPort': int(SSH_PORT),
                            'ToPort': int(SSH_PORT),
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }
                    ],
                )
            else:
                rules_apicall = client.authorize_security_group_ingress(
                    GroupId=created_sg_id,
                    IpPermissions=[
                        {
                            'IpProtocol': 'udp',
                            'FromPort': 500,
                            'ToPort': 500,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        },
                        {
                            'IpProtocol': 'udp',
                            'FromPort': 4500,
                            'ToPort': 4500,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        },
                        {
                            'IpProtocol': 'udp',
                            'FromPort': 1701,
                            'ToPort': 1701,
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        },
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': int(SSH_PORT),
                            'ToPort': int(SSH_PORT),
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


def get_instance_id():
    check_instances_apicall = client.describe_instances(
        Filters=[
            {
                'Name': 'subnet-id',
                'Values': [subnet_box.get()]
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
    check_creds()
    check_ports()
    check_fields()

    instance_id = get_instance_id()
    if instance_id:
        showinfo('Info', f'{PROTOCOL_NAME} VPN server already exists in subnet {subnet_box.get()}. InstanceId is {instance_id[0]["Instances"][0]["InstanceId"]}, public IP {instance_id[0]["Instances"][0]["PublicIpAddress"]}')
    else:
        print(f'No {PROTOCOL_NAME} VPN server found in subnet {subnet_box.get()}, creating one...') 
        
        image_id = get_ami()
        security_group_id = configure_security_groups()
        create_role()
        ec2_profile = get_profile_name_arn()

        key_name = 'vpn_ssh_' + str(datetime.now().strftime('%Y%m%d%H%M%S'))
        keypair_apicall = client.create_key_pair(KeyName=key_name, KeyType='rsa')
        with open(key_name, 'w') as file:
            file.write(keypair_apicall['KeyMaterial'])

        if PROTOCOL_NAME == 'Wireguard':
            with open('wireguard_install.sh', 'r') as install_script:
                init_install = install_script.read()
                init_install = init_install.replace('*ssh_port*', SSH_PORT)
                init_install = init_install.replace('*wg_port*', WG_PORT)
        else:
            with open('ipsec_install.sh', 'r') as install_script:
                init_install = install_script.read()
                init_install = init_install.replace('*ssh_port*', SSH_PORT)

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
                DryRun=True,
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
                        'SubnetId': subnet_box.get(),
                        'InterfaceType': 'interface',
                    },
                ],
                UserData=init_install,
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
            showerror('Error', f'Error in server configuration. Can\'t create server in subnet {subnet_box.get()}.')
        
        instance_id = get_instance_id()
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
                showinfo('Success', 'Instance is ready.')
                instance_id = get_instance_id()
                print(f'InstanceId is {instance_id[0]["Instances"][0]["InstanceId"]}, public IP {instance_id[0]["Instances"][0]["PublicIpAddress"]}')
                break
            elif timeout_check == CREATION_TIMEOUT_MINS * 6:
                showerror('Timeout', f'Instance creation exceeded {CREATION_TIMEOUT_MINS} minutes. Stopping...')
                break
            else: 
                print('Instance still being created...')
                time.sleep(10)
                timeout_check += 1


def create_peer():
    ssm_client = boto3.client('ssm', config=Config)  # Need your credentials here
    instance_id = get_instance_id()[0]['Instances'][0]['InstanceId']
    
    if instance_id:
        vpc_cidr_block = client.describe_vpcs(VpcIds=[VPC_ID])['Vpcs'][0]['CidrBlock']
        used_octets = vpc_cidr_block.split('.')[0] + '.' + vpc_cidr_block.split('.')[1]
        peer_private_ips = used_octets + '.69.0/24'
        if PROTOCOL_NAME == 'Wireguard':
            with open('wireguard_create_peer.sh', 'r') as peer_script:
                create_peer = peer_script.read()
                create_peer = create_peer.replace('*peer_name*', PEER_NAME)
                create_peer = create_peer.replace('*wg_port*', WG_PORT)
                create_peer = create_peer.replace('*peer_private_ips*', peer_private_ips)
        else:
            with open('ipsec_create_peer.sh', 'r') as peer_script:
                create_peer = peer_script.read()
                create_peer = create_peer.replace('*username*', USERNAME)
                create_peer = create_peer.replace('*password*', PASSWORD)

        exec_script = ssm_client.send_command(
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [create_peer]},
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
        showerror('Error', f'No {PROTOCOL_NAME} VPN server found. Please, create one.')

# aws iam delete-role --role-name EC2SSMrole
# aws iam delete-instance-profile --instance-profile-name EC2SSMprofile


root = Tk()
root.title('vpn-aws')
root.geometry('700x700')

aws_access_key = Entry(root, width=30)  
aws_secret_key = Entry(root, width=30)  
aws_region = Entry(root, width=10)

Label(root, text='AWS access key:').place(x=10, y=10)
aws_access_key.place(x=150, y=10)

Label(root, text='AWS secret key:').place(x=10, y=40)
aws_secret_key.place(x=150, y=40)

Label(root, text='AWS region:').place(x=10, y=70)
aws_region.place(x=150, y=70)

def check_creds():
    try:
        Config = botocore.config.Config(region_name=aws_region.get())
        sts = boto3.client(
            'sts',
            aws_access_key_id=aws_access_key.get(),
            aws_secret_access_key=aws_secret_key.get(),
            config=Config
        )
        sts.get_caller_identity()
    except Exception:
        showerror('Error', 'Credentials are not valid. Check your AWS policies, credentials or region.')


vpc_id = Entry(root, width=20)

Label(root, text='VPC ID:').place(x=10, y=100)
vpc_id.place(x=150, y=100)

Label(root, text='Subnet ID:').place(x=400, y=100)
subnet_box = ttk.Combobox(root, values=['-'])
subnet_box.place(x=480, y=100)
subnet_box.current(0)

Button(root, text='Get public subnets', command=get_public_subnets).place(x=500, y=30)

Label(root, text='VPN protocol choice:').place(x=270, y=170)

def wireguard_choice():
    global PROTOCOL_NAME
    wireguard_port.configure(state='normal')
    wireguard_peer_name.configure(state='normal')
    ipsec_username.configure(state='disabled')
    ipsec_password.configure(state='disabled')

    wireguard_port.update()
    wireguard_peer_name.update()
    ipsec_username.update()
    ipsec_password.update()
    PROTOCOL_NAME = 'Wireguard'


def ipsec_choice():
    global PROTOCOL_NAME
    wireguard_port.configure(state='disabled')
    wireguard_peer_name.configure(state='disabled')
    ipsec_username.configure(state='normal')
    ipsec_password.configure(state='normal')
    
    wireguard_port.update()
    wireguard_peer_name.update()
    ipsec_username.update()
    ipsec_password.update()
    PROTOCOL_NAME = 'IPsec'


frame = Frame(root, width=50, height=0)
frame.place(x=0, y=200)
var = StringVar()
rb_wireguard = Radiobutton(frame, text='Wireguard', variable=var, value='0', command=wireguard_choice).pack(side='left', ipadx=125)
rb_ipsec = Radiobutton(frame, text='IPsec', variable=var, value='1', command=ipsec_choice).pack(side='left', ipadx=125)

wireguard_port = Entry(root, width=10)
wireguard_peer_name = Entry(root, width=20)

Label(root, text='Port:').place(x=30, y=250)
wireguard_port.place(x=130, y=250)

Label(root, text='Peer name:').place(x=30, y=280)
wireguard_peer_name.place(x=130, y=280)

ipsec_username = Entry(root, width=15)
ipsec_password = Entry(root, width=15, show='*')

Label(root, text='Username:').place(x=400, y=250)
ipsec_username.place(x=500, y=250)

Label(root, text='Password:').place(x=400, y=280)
ipsec_password.place(x=500, y=280)

ipsec_username.configure(state='disabled')
ipsec_password.configure(state='disabled')

p = StringVar()
p.set('22')
ssh_port = Entry(root, textvariable=p, width=7)
Label(root, text='SSH port:').place(x=280, y=380)
ssh_port.place(x=350, y=380)

def check_ports():
    global SSH_PORT, WG_PORT

    if ssh_port.get() and int(ssh_port.get()) in list(range(1024, 32767)) + [22]:
        SSH_PORT = ssh_port.get()
        print(f'SSH port to use: {SSH_PORT}')
    else:
        try:
            raise ValueError('SSH port should be valid (22 or 1024-32767)')
        except Exception:
            showerror('Error', 'SSH port should be valid (22 or 1024-32767)')
    
    print(PROTOCOL_NAME)
    if PROTOCOL_NAME == 'Wireguard':
        if wireguard_port.get() and int(wireguard_port.get()) in list(range(49152, 65530)):
            WG_PORT = wireguard_port.get()
            print(f'Wireguard port to use: {WG_PORT}')
        else:
            try:
                raise ValueError('Wireguard port should be valid (49152-65530)')
            except Exception:
                showerror('Error', 'Wireguard port should be valid (49152-65530)')


def check_fields():
    global PEER_NAME, USERNAME, PASSWORD
    if PROTOCOL_NAME == 'Wireguard':
        if wireguard_peer_name.get().isalnum():
            PEER_NAME = wireguard_peer_name.get()
        else:
            try:
                raise ValueError('Provide peer name without special characters')
            except Exception:
                showerror('Error', 'Provide peer name without special characters')
    else: 
        if ipsec_username.get().isalnum() and ipsec_password.get().isalnum():
            USERNAME = ipsec_username.get()
            PASSWORD = ipsec_password.get()
        else:
            try:
                raise ValueError('Provide username and password without special characters')
            except Exception:
                showerror('Error', 'Provide username and password without special characters')


Button(root, text='CREATE SERVER', command=create_ec2_instance_main, width=20, height=3, borderwidth=10).place(x=250, y=450)

root.mainloop()
