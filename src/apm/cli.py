""" need to refactor this into better parts...
"""

import logging
import logging.config
import os
import json

import yaml
import boto3
import botocore

from botocore.exceptions import ClientError

import apm.jobs

NAME_PREFIX = "APM-"  # AWS permission manager

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)

# sh = logging.StreamHandler()
# formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# sh.setFormatter(formatter)
# logger.addHandler(sh)


def get_permission_sets(sso_client: botocore.client, identity_center_arn: str):
    """do something with the data structure candidate for moving into a class/module depending on the version"""

    ## List permission set ARNs
    permission_set_arns = []
    next_token = ""

    response = sso_client.list_permission_sets(InstanceArn=identity_center_arn)

    next_token = response.setdefault("NextToken", "")
    permission_set_arns.extend(response["PermissionSets"])

    while next_token != "":
        response = sso_client.list_permission_sets(
            InstanceArn=identity_center_arn, NextToken=next_token
        )

        permission_set_arns.extend(response["PermissionSets"])
        next_token = response["NextToken"]

    logger.debug("Permission set ARNs: %s", permission_set_arns)

    # Get permission set details
    permission_sets = {}
    for arn in permission_set_arns:
        response = sso_client.describe_permission_set(
            InstanceArn=identity_center_arn, PermissionSetArn=arn
        )
        permission_sets[response["PermissionSet"]["Name"]] = response["PermissionSet"]

    logger.debug(
        "Returning permission sets: %s",
        json.dumps(permission_sets, indent=2, default=str),
    )

    return permission_sets


# Create a permission
def create_permission_set(
    sso_client: botocore.client, identity_center_arn: str, name: str
):
    """Creates a permission set based on name passed in"""
    response = None
    logger.info("Creating permission set: %s", name)
    try:
        response = sso_client.create_permission_set(
            InstanceArn=identity_center_arn,
            Name=name,
            Description=f"Permission set for job: {name}",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConflictException":
            logger.info("Permission set already exists: %s", {name})
        else:
            raise e
    permission_set_arn = response["PermissionSet"]["PermissionSetArn"]

    logger.info("Created permission set, ARN: %s", permission_set_arn)

    return response["PermissionSet"]


def delete_permission_set(
    sso_client: botocore.client, identity_center_arn: str, permission_set_arn: str
):
    """Deletes specified permission set"""
    sso_client.delete_permission_set(
        InstanceArn=identity_center_arn, PermissionSetArn=permission_set_arn
    )


# update permission set policies to match what is passed in
def manage_permission_set_policies(
    sso_client: botocore.client,
    identity_center_arn: str,
    permission_set_arn: str,
    policies: [],
):
    """Adds or removes IAM policies to a permission set"""
    logger.info("Managing policies on permission set: %s", permission_set_arn)
    # Get existing permission set policies
    current_managed_policies = []
    current_customer_policies = []

    response = sso_client.list_customer_managed_policy_references_in_permission_set(
        InstanceArn=identity_center_arn,
        MaxResults=100,
        PermissionSetArn=permission_set_arn,
    )

    current_customer_policies = response["CustomerManagedPolicyReferences"]

    response = sso_client.list_managed_policies_in_permission_set(
        InstanceArn=identity_center_arn,
        MaxResults=100,
        PermissionSetArn=permission_set_arn,
    )

    current_managed_policies = response["AttachedManagedPolicies"]

    # Sort policies passed in into customer and aws managed
    new_managed_policies = [policy for policy in policies if "aws:policy/" in policy]
    new_customer_policies = [
        policy for policy in policies if "aws:policy/" not in policy
    ]

    # Compare desired policies to current policies
    # Convert to sets to easily find the differences
    current_managed_policy_set = {policy["Arn"] for policy in current_managed_policies}

    logger.info("Current managed policies: %s", current_managed_policy_set)
    new_managed_policy_set = set(new_managed_policies)
    logger.info("New managed policies: %s", new_managed_policy_set)

    # Items to delete
    to_delete = current_managed_policy_set.difference(new_managed_policies)
    logger.info("Managed policies to remove: %s", to_delete)
    for policy in to_delete:
        sso_client.detach_managed_policy_from_permission_set(
            InstanceArn=identity_center_arn,
            ManagedPolicyArn=policy,
            PermissionSetArn=permission_set_arn,
        )

    # Items to add
    to_add = new_managed_policy_set.difference(current_managed_policy_set)
    logger.info("Managed policies to add: %s", to_add)

    for policy in to_add:
        sso_client.attach_managed_policy_to_permission_set(
            InstanceArn=identity_center_arn,
            ManagedPolicyArn=policy,
            PermissionSetArn=permission_set_arn,
        )

    # Concat of the existing policies for doing the compare, and then a split for doing the create + delete....
    concat_existing_policies = [
        policy["Path"] + policy["Name"] for policy in current_customer_policies
    ]

    # Do set comparisons
    current_customer_set = set(concat_existing_policies)
    new_customer_set = set(new_customer_policies)

    # Detach policies that are not in the new set
    to_delete = current_customer_set.difference(new_customer_set)

    # Attach policies not in the current set
    to_add = new_customer_set.difference(current_customer_set)

    for policy in to_delete:
        pass

    for policy in to_add:
        pass


def manage_permissions(
    sso_client: botocore.client, identity_center_arn: str, job_definitions: {}
):
    """Coordinates the creation of permission sets and their IAM policies"""

    # Get existing list of permission sets to check against
    permission_sets = get_permission_sets(
        sso_client=sso_client, identity_center_arn=identity_center_arn
    )

    for job_name, job_definition in job_definitions.items():
        if job_name not in permission_sets:
            # Create permission set for the job
            permission_set = create_permission_set(
                sso_client=sso_client,
                identity_center_arn=identity_center_arn,
                name=job_name,
            )

            permission_sets[job_name] = permission_set

        else:
            logger.info("Permission set exists: %s", job_name)

        manage_permission_set_policies(
            sso_client=sso_client,
            identity_center_arn=identity_center_arn,
            permission_set_arn=permission_sets[job_name]["PermissionSetArn"],
            policies=job_definition["policies"],
        )

        for set_key, set_value in permission_sets.items():
            if NAME_PREFIX not in set_key:
                logger.info("Permission set not managed by APM skipping: %s", set_key)
                continue

            if set_key not in job_definitions:
                logger.info("Permission set marked for deletion: %s", set_key)
                delete_permission_set(
                    sso_client=sso_client,
                    identity_center_arn=identity_center_arn,
                    permission_set_arn=set_value["PermissionSetArn"],
                )
            else:
                logger.info("Permission set exists in job function list: %s", set_key)


def get_groups(is_client: botocore.client, identity_store_id: str):
    """Gets a list of AWS groups and keys them on name"""
    logger.info("Getting list of groups")
    groups = []

    response = is_client.list_groups(IdentityStoreId=identity_store_id, MaxResults=100)

    groups.extend(response["Groups"])
    next_token = response.setdefault("NextToken", "")

    while next_token != "":
        response = is_client.list_groups(
            IdentityStoreId=identity_store_id, MaxResults=100
        )
        groups.extend(response["Groups"])
        next_token = response.setdefault("NextToken", "")

    # Reformat data so easier to do lookups on name when processing
    group_dict = {}
    for item in groups:
        group_dict[item["DisplayName"]] = item

    logger.debug("Returning groups: %s", group_dict)
    return group_dict


def create_group(is_client: botocore.client, identity_store_id: str, group_name: str):
    """SImple wrapper to create a group"""
    response = is_client.create_group(
        IdentityStoreId=identity_store_id,
        DisplayName=group_name,
        Description=f"Group for job function:{group_name}",
    )

    result = {
        group_name: {
            "GroupId": response["GroupId"],
            "IdentityStoreId": response["IdentityStoreId"],
            "DisplayName": group_name,
        }
    }
    return result


def delete_group(is_client: botocore.client, identity_store_id: str, group_id: str):
    """Delete a group given the id"""
    logger.info("Deleting group: %s", group_id)
    is_client.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)


def manage_groups(
    is_client: botocore.client, identity_store_id: str, job_definitions: {}
):
    """Creates or deletes groups as required based on job definitions"""
    logger.info("Starting group management")

    groups = get_groups(is_client=is_client, identity_store_id=identity_store_id)

    # Create as necessary
    for job_name, job_definition in job_definitions.items():
        if job_name not in groups:
            logger.debug("Group not found: %s", job_name)
            create_group(
                is_client=is_client,
                identity_store_id=identity_store_id,
                group_name=job_name,
            )

    # Delete as necessary
    for group in groups:
        if NAME_PREFIX not in group:
            logger.info("Group not managed by permissions manager: %s", group)
            continue

        if group not in job_definitions:
            logger.info(
                "Group not found in current jobs, marked for deletion: %s", group
            )
            delete_group(
                is_client=is_client,
                identity_store_id=identity_store_id,
                group_id=groups[group]["GroupId"],
            )

    logger.info("Completed group management")


def assign_account(
    sso_client: botocore.client,
    identity_center_arn: str,
    permission_set_arn: str,
    group_id: str,
    account_id: str,
):
    """AWS call to do the permission and group assignment to an account"""
    response = sso_client.create_account_assignment(
        InstanceArn=identity_center_arn,
        PermissionSetArn=permission_set_arn,
        PrincipalId=group_id,
        PrincipalType="GROUP",
        TargetId=account_id,
        TargetType="AWS_ACCOUNT",
    )
    logger.info(
        "Assign account response: %s", response["AccountAssignmentCreationStatus"]
    )


def apply_permissions(
    sso_client: botocore.client,
    is_client: botocore.client,
    identity_center_arn: str,
    identity_store_id: str,
    job_definitions: {},
):
    """Apply the permission sets and groups to accounts"""
    logger.info("Applying permission sets and groups to accounts")

    permission_sets = get_permission_sets(
        sso_client=sso_client, identity_center_arn=identity_center_arn
    )
    groups = get_groups(is_client=is_client, identity_store_id=identity_store_id)

    for job, details in job_definitions.items():
        logger.info("Processing job function %s", job)
        for account in details["scope"]["accounts"]:
            logging.info(
                "Assigning account: %s group: %s permission_set: %s",
                account,
                groups[job]["GroupId"],
                permission_sets[job]["PermissionSetArn"],
            )
            assign_account(
                sso_client=sso_client,
                identity_center_arn=identity_center_arn,
                permission_set_arn=permission_sets[job]["PermissionSetArn"],
                group_id=groups[job]["GroupId"],
                account_id=account,
            )


def start():
    """Kick things off"""

    f = open("config/logging.yaml")
    logging_config = yaml.safe_load(f.read())
    logging.config.dictConfig(logging_config)

    identity_center_arn = os.environ["IDENTITY_CENTER_ARN"]
    identity_store_id = os.environ["IDENTITY_STORE_ID"]

    # Parse out job definitions
    job_path = "job_definitions"
    job_definitions = apm.jobs.get_jobs(job_path, NAME_PREFIX)

    if len(job_definitions.keys()) == 0:
        logger.error("No job definitions loaded from path: %s", job_path)

    # Manage the permissions and policies
    sso_client = boto3.client("sso-admin")

    manage_permissions(
        sso_client=sso_client,
        identity_center_arn=identity_center_arn,
        job_definitions=job_definitions,
    )

    # Create/update/delete customer managed policies in accounts
    # manage_policies()

    # Create/update/delete groups
    is_client = boto3.client("identitystore")
    manage_groups(
        is_client=is_client,
        identity_store_id=identity_store_id,
        job_definitions=job_definitions,
    )

    apply_permissions(
        sso_client=sso_client,
        is_client=is_client,
        identity_center_arn=identity_center_arn,
        identity_store_id=identity_store_id,
        job_definitions=job_definitions,
    )


if __name__ == "__main__":
    start()
