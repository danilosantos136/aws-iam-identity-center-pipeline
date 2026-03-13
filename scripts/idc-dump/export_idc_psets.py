#!/usr/bin/env python3
"""
AWS IAM Identity Center Permission Sets Export Script

This script exports IAM Identity Center permission sets for migration purposes.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


class IDCPermissionSetExporter:
    """Exports IAM Identity Center permission sets."""

    def __init__(
        self,
        profile: str,
        region: str,
        export_dir: str,
        permission_set: Optional[str] = None,
        include_aws_managed: bool = False,
        account_id: Optional[str] = None,
    ):
        """Initialize the exporter."""
        self.profile = profile
        self.region = region
        self.export_dir = Path(export_dir)
        self.filter_permission_set = permission_set
        self.include_aws_managed = include_aws_managed
        self.filter_account_id = account_id

        # Initialize AWS clients
        session = boto3.Session(profile_name=profile, region_name=region)
        self.sso_admin = session.client("sso-admin")
        self.access_analyzer = session.client("accessanalyzer")

        # Create export directories
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self.pset_dir = self.export_dir / "permissionsets"
        self.pset_dir.mkdir(exist_ok=True)

    def is_aws_managed_permission_set(self, instance_arn: str, ps_arn: str) -> bool:
        """Check if a permission set is AWS-managed (predefined)."""
        try:
            response = self.sso_admin.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn
            )
            ps = response["PermissionSet"]
            
            # AWS-managed permission sets have specific characteristics:
            # 1. They are created by AWS (CreatedBy field might indicate this)
            # 2. They typically have AWS-managed policies attached
            # 3. They often have standardized names like "AWSAdministratorAccess"
            
            # Check if it's a well-known AWS-managed permission set name
            aws_managed_names = {
                "AWSAdministratorAccess",
                "AWSPowerUserAccess", 
                "AWSReadOnlyAccess",
                "AWSOrganizationsFullAccess",
                "AWSServiceCatalogAdminFullAccess",
                "AWSServiceCatalogEndUserAccess",
                "AWSSupportAccess",
                "AWSBillingReadOnlyAccess",
                "AWSViewOnlyAccess"
            }
            
            ps_name = ps.get("Name", "")
            if ps_name in aws_managed_names:
                return True
            
            # Additional check: if permission set only has AWS managed policies and no custom policies
            try:
                # Get managed policies
                managed_policies = []
                paginator = self.sso_admin.get_paginator("list_managed_policies_in_permission_set")
                for page in paginator.paginate(
                    InstanceArn=instance_arn,
                    PermissionSetArn=ps_arn
                ):
                    managed_policies.extend([p["Arn"] for p in page.get("AttachedManagedPolicies", [])])
                
                # Get customer managed policies
                customer_policies = []
                try:
                    paginator = self.sso_admin.get_paginator("list_customer_managed_policy_references_in_permission_set")
                    for page in paginator.paginate(
                        InstanceArn=instance_arn,
                        PermissionSetArn=ps_arn
                    ):
                        customer_policies.extend([p["Name"] for p in page.get("CustomerManagedPolicyReferences", [])])
                except ClientError:
                    pass
                
                # Check for inline policy
                has_inline_policy = False
                try:
                    response = self.sso_admin.get_inline_policy_for_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=ps_arn
                    )
                    inline_policy = response.get("InlinePolicy")
                    if inline_policy and inline_policy.strip():
                        has_inline_policy = True
                except ClientError:
                    pass
                
                # If it has only AWS managed policies and no custom policies/inline policies,
                # and the name suggests it's AWS-managed, consider it AWS-managed
                if (managed_policies and 
                    not customer_policies and 
                    not has_inline_policy and
                    all(policy.startswith("arn:aws:iam::aws:policy/") for policy in managed_policies)):
                    
                    # Additional heuristic: AWS-managed permission sets often have simple names
                    # that match or are similar to the AWS managed policy names
                    for policy_arn in managed_policies:
                        policy_name = policy_arn.split("/")[-1]
                        if ps_name == policy_name or ps_name.replace("AWS", "") == policy_name:
                            return True
                
            except ClientError:
                pass
            
            return False
            
        except ClientError:
            # If we can't determine, assume it's custom to be safe
            return False

    def get_sso_instance(self) -> str:
        """Get SSO instance ARN."""
        response = self.sso_admin.list_instances()
        if not response.get("Instances"):
            raise ValueError("No IAM Identity Center instance found")

        instance = response["Instances"][0]
        return instance["InstanceArn"]

    def has_account_assignment(self, instance_arn: str, ps_arn: str, account_id: str) -> bool:
        """Check if a permission set has assignments for the specified account."""
        try:
            paginator = self.sso_admin.get_paginator("list_account_assignments")
            for page in paginator.paginate(
                InstanceArn=instance_arn,
                AccountId=account_id,
                PermissionSetArn=ps_arn
            ):
                if page.get("AccountAssignments"):
                    return True
            return False
        except ClientError as e:
            print(f"  Warning: Could not check assignments for permission set: {e}")
            return False

    def validate_and_fix_policy(self, policy_document: Dict, ps_name: str) -> tuple:
        """
        Validate a policy document using AWS Access Analyzer and fix invalid actions.
        
        Args:
            policy_document: The IAM policy document to validate
            ps_name: Permission set name for logging
            
        Returns:
            Tuple of (fixed_policy_document, was_modified)
        """
        if not policy_document:
            return policy_document, False
        
        modified = False
        max_iterations = 5  # Prevent infinite loops
        iteration = 0
        
        while iteration < max_iterations:
            iteration += 1
            
            try:
                # Convert policy document to JSON string
                policy_json = json.dumps(policy_document)
                
                # Call Access Analyzer validate_policy API
                response = self.access_analyzer.validate_policy(
                    policyDocument=policy_json,
                    policyType="IDENTITY_POLICY"
                )
                
                # Process findings
                findings = response.get("findings", [])
                invalid_actions_found = False
                actions_to_remove = []
                
                for finding in findings:
                    finding_type = finding.get("findingType")
                    issue_code = finding.get("issueCode")
                    finding_details = finding.get("findingDetails", "")
                    
                    # Check for invalid action errors
                    if finding_type == "ERROR" and "does not exist" in finding_details.lower():
                        invalid_actions_found = True
                        # Extract the invalid action from the finding details
                        # Typical format: "The action <action> does not exist"
                        import re
                        action_match = re.search(r"action[s]?\s+([^\s]+)\s+does not exist", finding_details, re.IGNORECASE)
                        if action_match:
                            invalid_action = action_match.group(1).strip("'\"")
                            actions_to_remove.append(invalid_action)
                            print(f"    🔧 Found invalid action: {invalid_action}")
                    
                    # Log all findings
                    if finding_type == "ERROR":
                        print(f"    ❌ ERROR: {issue_code} - {finding_details}")
                    elif finding_type == "WARNING":
                        print(f"    ⚠️  WARNING: {issue_code} - {finding_details}")
                    elif finding_type == "SUGGESTION":
                        print(f"    💡 SUGGESTION: {issue_code} - {finding_details}")
                    elif finding_type == "SECURITY_WARNING":
                        print(f"    🔒 SECURITY WARNING: {issue_code} - {finding_details}")
                
                # If invalid actions found, remove them and retry validation
                if invalid_actions_found and actions_to_remove:
                    print(f"    🔧 Removing {len(actions_to_remove)} invalid action(s) from policy...")
                    policy_document = self._remove_actions_from_policy(policy_document, actions_to_remove)
                    modified = True
                    continue  # Retry validation with fixed policy
                
                # If no invalid actions or no more findings, we're done
                if not findings:
                    print("    ✅ Policy validation passed with no findings")
                elif not invalid_actions_found:
                    # Policy has warnings/suggestions but no invalid actions
                    print("    ✅ Policy validation completed (warnings/suggestions present)")
                
                break  # Exit loop
                
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                error_message = e.response.get("Error", {}).get("Message", str(e))
                print(f"    ❌ Access Analyzer API Error: {error_code} - {error_message}")
                break  # Exit on API error
            except Exception as e:
                print(f"    ❌ Unexpected validation error: {e}")
                break  # Exit on unexpected error
        
        if iteration >= max_iterations:
            print(f"    ⚠️  Warning: Reached maximum validation iterations ({max_iterations})")
        
        return policy_document, modified
    
    def _remove_actions_from_policy(self, policy_document: Dict, actions_to_remove: List[str]) -> Dict:
        """
        Remove specific actions from a policy document.
        
        Args:
            policy_document: The IAM policy document
            actions_to_remove: List of action strings to remove
            
        Returns:
            Modified policy document
        """
        import copy
        policy = copy.deepcopy(policy_document)
        
        if "Statement" not in policy:
            return policy
        
        for statement in policy["Statement"]:
            if "Action" not in statement:
                continue
            
            actions = statement["Action"]
            
            # Handle both string and list formats
            if isinstance(actions, str):
                if actions in actions_to_remove:
                    # If single action matches, remove the entire statement or set to empty list
                    statement["Action"] = []
            elif isinstance(actions, list):
                # Filter out invalid actions
                original_count = len(actions)
                statement["Action"] = [
                    action for action in actions 
                    if action not in actions_to_remove
                ]
                removed_count = original_count - len(statement["Action"])
                if removed_count > 0:
                    print(f"      Removed {removed_count} action(s) from statement")
        
        # Remove statements with empty Action lists
        policy["Statement"] = [
            stmt for stmt in policy["Statement"]
            if stmt.get("Action") and (
                isinstance(stmt["Action"], list) and len(stmt["Action"]) > 0
                or isinstance(stmt["Action"], str)
            )
        ]
        
        return policy

    def export_permission_sets(self, instance_arn: str) -> List[Dict]:
        """Export all permission sets."""
        print("\n=== Exporting Permission Sets ===")
        
        permission_sets = []
        paginator = self.sso_admin.get_paginator("list_permission_sets")
        
        for page in paginator.paginate(InstanceArn=instance_arn):
            permission_sets.extend(page["PermissionSets"])

        # Filter permission sets based on AWS-managed flag
        if not self.include_aws_managed:
            print("Filtering out AWS-managed permission sets...")
            filtered_permission_sets = []
            for ps_arn in permission_sets:
                if not self.is_aws_managed_permission_set(instance_arn, ps_arn):
                    filtered_permission_sets.append(ps_arn)
                else:
                    # Get name for logging
                    try:
                        response = self.sso_admin.describe_permission_set(
                            InstanceArn=instance_arn,
                            PermissionSetArn=ps_arn
                        )
                        ps_name = response["PermissionSet"]["Name"]
                        print(f"  Skipping AWS-managed permission set: {ps_name}")
                    except ClientError:
                        print(f"  Skipping AWS-managed permission set: {ps_arn}")
            
            permission_sets = filtered_permission_sets
            print(f"Filtered to {len(permission_sets)} custom permission sets")
        else:
            print("Including both custom and AWS-managed permission sets")

        # Filter permission sets based on account assignments
        if self.filter_account_id:
            print(f"Filtering permission sets with assignments for account: {self.filter_account_id}")
            filtered_permission_sets = []
            for ps_arn in permission_sets:
                # Get name for logging
                try:
                    response = self.sso_admin.describe_permission_set(
                        InstanceArn=instance_arn,
                        PermissionSetArn=ps_arn
                    )
                    ps_name = response["PermissionSet"]["Name"]
                    
                    if self.has_account_assignment(instance_arn, ps_arn, self.filter_account_id):
                        filtered_permission_sets.append(ps_arn)
                        print(f"  Including permission set with assignment: {ps_name}")
                    else:
                        print(f"  Skipping permission set without assignment: {ps_name}")
                except ClientError as e:
                    print(f"  Warning: Could not check permission set {ps_arn}: {e}")
            
            permission_sets = filtered_permission_sets
            print(f"Filtered to {len(permission_sets)} permission sets with assignments for account {self.filter_account_id}")

        # Save permission set ARNs
        ps_file = self.export_dir / "permission_sets.txt"
        with open(ps_file, "w") as f:
            f.write("\n".join(permission_sets))

        print(f"Found {len(permission_sets)} permission sets to export")

        # Export each permission set details
        ps_details_list = []
        for idx, ps_arn in enumerate(permission_sets, 1):
            ps_details = self.export_permission_set_details(instance_arn, ps_arn, idx, len(permission_sets))
            if not ps_details.get("Skipped"):
                ps_details_list.append(ps_details)

        return ps_details_list

    def export_permission_set_details(
        self, 
        instance_arn: str, 
        ps_arn: str, 
        index: int, 
        total: int
    ) -> Dict:
        """Export details for a single permission set."""
        # Get permission set details
        response = self.sso_admin.describe_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn
        )
        ps = response["PermissionSet"]
        ps_name = ps["Name"]

        # Apply filter if specified
        if self.filter_permission_set and ps_name != self.filter_permission_set:
            return {"Name": ps_name, "Arn": ps_arn, "Skipped": True}

        print(f"[{index}/{total}] Exporting: {ps_name}")

        # Get managed policies
        managed_policies = []
        try:
            paginator = self.sso_admin.get_paginator("list_managed_policies_in_permission_set")
            for page in paginator.paginate(
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn
            ):
                managed_policies.extend([p["Arn"] for p in page.get("AttachedManagedPolicies", [])])
        except ClientError:
            pass

        # Get customer managed policies
        customer_policies = []
        try:
            paginator = self.sso_admin.get_paginator("list_customer_managed_policy_references_in_permission_set")
            for page in paginator.paginate(
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn
            ):
                customer_policies.extend([p["Name"] for p in page.get("CustomerManagedPolicyReferences", [])])
        except ClientError:
            pass

        # Get inline policy
        custom_policy = {}
        policy_was_modified = False
        try:
            response = self.sso_admin.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn
            )
            inline_policy = response.get("InlinePolicy")
            if inline_policy:
                custom_policy = json.loads(inline_policy)
                
                # Validate and fix custom policy with Access Analyzer
                print(f"  Validating custom policy for {ps_name}...")
                custom_policy, policy_was_modified = self.validate_and_fix_policy(custom_policy, ps_name)
                
                if policy_was_modified:
                    print(f"  ✅ Custom policy was modified to remove invalid actions")
        except ClientError:
            pass

        # Build consolidated permission set data
        description = ps.get("Description", "").strip()
        relay_state = ps.get("RelayState", "").strip()
        
        ps_data = {
            "Name": ps_name,
            "Description": description if description else ps_name,
            "SessionDuration": ps.get("SessionDuration", ""),
            "ManagedPolicies": managed_policies,
            "CustomerManagedPolicies": customer_policies,
            "PermissionBoundary": ps.get("PermissionsBoundary", {}),
            "CustomPolicy": custom_policy
        }
        
        # Only include RelayState if it's not empty
        if relay_state:
            ps_data["RelayState"] = relay_state

        # Save to file
        safe_name = ps_name.replace("/", "_").replace(" ", "_")
        ps_file = self.pset_dir / f"ps_{safe_name}.json"
        with open(ps_file, "w") as f:
            json.dump(ps_data, f, indent=2)

        return {"Name": ps_name, "Arn": ps_arn, "Skipped": False}

    def run(self):
        """Run the export process."""
        print("AWS IAM Identity Center Permission Sets Export Script")
        print("=" * 55)
        print(f"Using AWS Profile: {self.profile}")
        print(f"Region: {self.region}")
        print(f"Export Directory: {self.export_dir}")
        print(f"Include AWS-managed Permission Sets: {self.include_aws_managed}")
        
        if self.filter_permission_set:
            print(f"Filtering by Permission Set: {self.filter_permission_set}")
        
        if self.filter_account_id:
            print(f"Filtering by Account ID: {self.filter_account_id}")

        try:
            # Get SSO instance
            instance_arn = self.get_sso_instance()
            print(f"\nInstance ARN: {instance_arn}")

            # Export permission sets
            permission_sets = self.export_permission_sets(instance_arn)

            print("\n" + "=" * 55)
            print("Permission Sets export completed successfully!")
            print(f"Results saved to: {self.pset_dir}")
            print(f"Exported {len(permission_sets)} permission sets")

        except Exception as e:
            print(f"\nError: {e}", file=sys.stderr)
            sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Export AWS IAM Identity Center permission sets"
    )
    parser.add_argument(
        "--profile",
        default=os.environ.get("AWS_PROFILE", "default"),
        help="AWS profile to use (default: AWS_PROFILE env var or 'default')"
    )
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        help="AWS region (default: AWS_DEFAULT_REGION env var or 'us-east-1')"
    )
    parser.add_argument(
        "--export-dir",
        default="./migration",
        help="Export directory (default: ./migration)"
    )
    parser.add_argument(
        "--permission-set",
        help="Filter by specific permission set name"
    )
    parser.add_argument(
        "--include-aws-managed",
        action="store_true",
        help="Include AWS-managed (predefined) permission sets in export (default: False, only custom permission sets)"
    )
    parser.add_argument(
        "--account-id",
        help="Filter permission sets to only those with assignments for the specified AWS account ID"
    )

    args = parser.parse_args()

    exporter = IDCPermissionSetExporter(
        profile=args.profile,
        region=args.region,
        export_dir=args.export_dir,
        permission_set=args.permission_set,
        include_aws_managed=args.include_aws_managed,
        account_id=args.account_id,
    )

    exporter.run()


if __name__ == "__main__":
    main()