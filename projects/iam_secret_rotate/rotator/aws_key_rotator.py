from aws_cdk import (
    Stack,
    Duration,
    SecretValue,
    aws_ses as ses,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_sns as sns,
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct


class AwsAccessKeyRotatorStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        ### Ensure that these identities are verified in SNS and SES beforehand
        email_source = "vlad.maracine.upb@gmail.com"
        notification_email = "vlad.maracine@yahoo.com"

        # SES Configuration
        self.setup_ses(email_source, notification_email)

        # SNS Topic and Subscription for failure notifications
        topic = self.setup_sns_topic(email_source)

        # Lambda Role with the necessary permissions
        lambda_role = self.create_lambda_role(topic)

        # Lambda Function to handle the access key rotation
        lambda_function = self.create_lambda_function(lambda_role, topic, email_source)

        # ONLY FOR TESTING PURPOSES: 
        # users = ['test-key-rotator']  
        # self.setup_secrets_rotation(lambda_function, users)

    def setup_ses(self, email_source: str, notification_email: str) -> None:
        ses.EmailIdentity(
            self,
            "NotificationEmailIdentity",
            identity=ses.Identity.email(notification_email),
        )

        ses.EmailIdentity(
            self,
            "SourceEmailIdentity",
            identity=ses.Identity.email(email_source),
        )

    def setup_sns_topic(self, email_source: str) -> sns.Topic:
        topic = sns.Topic(
            self,
            "FailureTopic",
            topic_name="access-key-rotation-notification"
        )

        sns.Subscription(
            self,
            "AdminSubscription",
            topic=topic,
            protocol=sns.SubscriptionProtocol.EMAIL,
            endpoint=email_source
        )

        return topic

    def create_lambda_role(self, topic: sns.Topic) -> iam.Role:
        return iam.Role(
            self,
            "LambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            role_name="access-key-rotator-role",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                iam.ManagedPolicy.from_aws_managed_policy_name("SecretsManagerReadWrite"),
                iam.ManagedPolicy.from_aws_managed_policy_name("IAMFullAccess")
            ],
            inline_policies={
                "SESPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["ses:SendEmail"],
                            effect=iam.Effect.ALLOW,
                            resources=["*"]  # Can be scoped to specific SES resources if needed
                        )
                    ]
                ),
                "SNSPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["sns:Publish"],
                            effect=iam.Effect.ALLOW,
                            resources=[topic.topic_arn]
                        )
                    ]
                )
            }
        )

    def create_lambda_function(self, role: iam.Role, topic: sns.Topic, email_source: str) -> lambda_.Function:
        function = lambda_.Function(
            self,
            "IAMSecretRotate",
            runtime=lambda_.Runtime.PYTHON_3_9,
            function_name="iam-secret-key-rotator",
            code=lambda_.Code.from_asset("./lambda"),  
            handler="lambda_function.lambda_handler",
            role=role,
            environment={
                "sns_topic_arn": topic.topic_arn,
                "source_email": email_source,
            },
            timeout=Duration.seconds(30)
        )

        function.add_permission(
            "SecretsManagerInvokePermission",
            principal=iam.ServicePrincipal("secretsmanager.amazonaws.com"),
        )

        return function

    def setup_secrets_rotation(self, lambda_function: lambda_.Function, users: list) -> None:
        for user in users:
            secret_name = f"/access-key/{user}"
            secret_id = f"{user.replace('.', '')}Secret"

            secret = secretsmanager.Secret(
                self,
                secret_id,
                secret_name=secret_name,
                secret_object_value={
                    "access_key_id": SecretValue.unsafe_plain_text("access_id_test"),  
                    "secret_access_key": SecretValue.unsafe_plain_text("secret_id_test")  
                }
            )

            secret.add_rotation_schedule(
                f"{user.replace('.', '')}Rotation",
                automatically_after=Duration.days(90),
                rotation_lambda=lambda_function
            )
