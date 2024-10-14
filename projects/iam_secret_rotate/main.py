#!/usr/bin/env python3
import os

import aws_cdk as cdk

from rotator import AwsAccessKeyRotatorStack


app = cdk.App()
AwsAccessKeyRotatorStack(app, "AwsAccessKeyRotatorStack",
    env=cdk.Environment(account='975050137696', region='us-east-1'),
    )

app.synth()