import yaml
import boto3
import botocore
import logging
import os
import json

from botocore.exceptions import ClientError

NAME_PREFIX = 'APM' # AWS permission manager

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

sh = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
sh.setFormatter(formatter)
logger.addHandler(sh)

# read yaml file so we get a dict that can be worked with
def parse_yaml(filename:str):
  output = {}
  with open(filename) as file:
    output = yaml.safe_load(file)

  return output

##
## do something with the data structure
## candidate for moving into a class/module depending on the version
##

def get_permission_sets(
    sso_client: botocore.client,
    identity_center_arn: str):
  
  ## List permission set ARNs
  permission_set_arns     = []
  next_token  = ''
  
  response = sso_client.list_permission_sets(
      InstanceArn = identity_center_arn)
  
  next_token = response.setdefault('NextToken', '')
  permission_set_arns.extend(response['PermissionSets'])
  
  while next_token != '':
    response = sso_client.list_permission_sets(
      InstanceArn = identity_center_arn,
      NextToken = next_token)

    permission_set_arns.extend(response['PermissionSets'])
    next_token = response['NextToken']
    
  logger.debug(f"Permission set ARNs: {permission_set_arns}")

  # Get permission set details
  permission_sets = {}
  for arn in permission_set_arns:
    response = sso_client.describe_permission_set(
      InstanceArn = identity_center_arn,
      PermissionSetArn = arn
    )
    permission_sets[response['PermissionSet']['Name']] = response['PermissionSet']

  logger.debug(f"Permission set details: {permission_sets}")
  
  return permission_sets


# Create a permission 
def create_permission_set(
    sso_client: botocore.client,
    identity_center_arn: str,
    name:str):
  
  response = None
  logger.info(f"Creating permission set: {name}")
  try:
    response = sso_client.create_permission_set(
      InstanceArn = identity_center_arn,
      Name        = name,
      Description = f"Permission set for job: {name}")
  except ClientError as e:
    if e.response['Error']['Code'] == 'ConflictException':
      logger.info(f"Permission set already exists: {name}")
    else:
      raise e
  permission_set_arn = response['PermissionSet']['PermissionSetArn']

  logger.info(f"Created permission set, ARN: {permission_set_arn}")

  return response['PermissionSet']

# update permission set policies to match what is passed in
def manage_permission_set_policies(
    sso_client: botocore.client,
    identity_center_arn: str,
    permission_set_arn: str,
    policies: []):
  
  logger.info(f"Managing policies on permission set: {permission_set_arn}")
  # Get existing permission set policies
  current_managed_policies = []
  current_customer_policies = []

  response = sso_client.list_customer_managed_policy_references_in_permission_set(
    InstanceArn = identity_center_arn,
    MaxResults = 100,
    PermissionSetArn = permission_set_arn)
  
  current_customer_policies = response['CustomerManagedPolicyReferences']
  
  response = sso_client.list_managed_policies_in_permission_set(
    InstanceArn = identity_center_arn,
    MaxResults = 100,
    PermissionSetArn = permission_set_arn)
  
  current_managed_policies = response['AttachedManagedPolicies']

  # Sort policies passed in into customer and aws managed
  new_managed_policies = [policy for policy in policies if "aws:policy/" in policy]
  new_customer_policies = [policy for policy in policies if "aws:policy/" not in policy]

  # Compare desired policies to current policies
  # Convert to sets to easily find the differences
  current_managed_policy_set  = set([policy['Arn'] for policy in current_managed_policies])
  logger.info(f"Current managed policies: {current_managed_policy_set}")
  new_managed_policy_set      = set(new_managed_policies)
  logger.info(f"New managed policies: {new_managed_policy_set}")

  # Items to delete
  to_delete = current_managed_policy_set.difference(new_managed_policies)
  logger.info(f"Managed policies to remove: {to_delete}")
  for policy in to_delete:
    sso_client.detach_managed_policy_from_permission_set(
      InstanceArn = identity_center_arn, 
      ManagedPolicyArn  = policy,
      PermissionSetArn  = permission_set_arn)


  # Items to add
  to_add = new_managed_policy_set.difference(current_managed_policy_set)
  logger.info(f"Managed policies to add: {to_add}")

  for policy in to_add:
    sso_client.attach_managed_policy_to_permission_set(
      InstanceArn = identity_center_arn, 
      ManagedPolicyArn = policy,
      PermissionSetArn = permission_set_arn)

  # Concat of the existing policies for doing the compare, and then a split for doing the create + delete....
  concat_existing_policies = [policy['Path'] + policy['Name'] for policy in current_customer_policies]

  # Do set comparisons
  current_customer_set = set(concat_existing_policies)
  new_customer_set     = set(new_customer_policies)

  # Detach policies that are not in the new set
  to_delete = current_customer_set.difference(new_customer_set)

  # Attach policies not in the current set
  to_add = new_customer_set.difference(current_customer_set)


  for policy in to_delete:
    pass

  for policy in to_add:
    pass


def process_definition(definition):
  pass
  # create a group based on the filename

  # create a permission set based on filename

  # attach policies to permission set

  # apply permission set, group to accounts

def manage_permissions(
    sso_client:botocore.client,
    identity_center_arn: str,
    job_definitions: {}):
  # Get existing list of permission sets to check against
  permission_sets = get_permission_sets(
    sso_client= sso_client,
    identity_center_arn=identity_center_arn)
  
  for job_name, job_definition in job_definitions.items():
    set_name = f"{NAME_PREFIX}-{job_name}"
    if set_name not in permission_sets:
      # Create permission set for the job
      permission_set = create_permission_set(
        sso_client=sso_client,
        identity_center_arn=identity_center_arn,
        name=set_name)
      
      permission_sets[set_name] = permission_set
      
    else:
      logger.info(f"Permission set exists: {set_name}")

    manage_permission_set_policies(
      sso_client=sso_client,
      identity_center_arn=identity_center_arn,
      permission_set_arn=permission_sets[job_name]['PermissionSetArn'],
      policies=job_definition['policies'])

    # TODO: delete permission sets that are not in the definition file
    
def manage_groups(
    is_client: botocore.client,
    identity_store_id: str,
    job_definitions: {}):

  groups = []
  
  # Get list of existing groups
  response = is_client.list_groups(
    IdentityStoreId=identity_store_id,
    MaxResults = 100)
  
  groups.extend(response['Groups'])
  next_token = response.setdefault('NextToken','')

  while next_token != '':
    response = is_client.list_groups(
      IdentityStoreId=identity_store_id,
      MaxResults = 100)
    groups.extend(response['Groups'])
    next_token = response.setdefault('NextToken','')

  logger.debug(groups)

  # Get list of groups from job defs

  for job_name, job_definition in job_definitions.items():
    pass


  # Get difference between the two sets

  # Create as necessary

  # Delete as necessary

if __name__ == "__main__":

  identity_center_arn = os.environ["IDENTITY_CENTER_ARN"]
  identity_store_id = os.environ["IDENTITY_STORE_ID"]


  # Parse out job definitions
  job_dir = 'job_definitions'
  job_files = os.listdir(job_dir)

  logger.debug(job_files)
  
  job_definitions = {}
  
  for file in job_files:
    job_name = file.split(sep='.')[0]
    job_definitions[job_name] = parse_yaml(f"{job_dir}/{file}")

  # Manage the permissions and policies
  sso_client = boto3.client("sso-admin")

  manage_permissions(
    sso_client=sso_client,
    identity_center_arn=identity_center_arn,
    job_definitions=job_definitions)
  
  # Create/update/delete customer managed policies in accounts
  #manage_policies()

  # Create/update/delete groups
  is_client = boto3.client('identitystore')
  manage_groups(
    is_client=is_client,
    identity_store_id=identity_store_id,
    job_definitions=job_definitions)
  
