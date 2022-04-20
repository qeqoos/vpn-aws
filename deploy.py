# import tkinter as tk
from distutils.command.config import config
import boto3
import botocore

# root = tk.Tk()
# root.mainloop()

Config = botocore.config.Config(region_name='us-east-2')

client = boto3.client(
    "ec2",
    aws_access_key_id="pass",
    aws_secret_access_key="pass",
    config=Config
)

