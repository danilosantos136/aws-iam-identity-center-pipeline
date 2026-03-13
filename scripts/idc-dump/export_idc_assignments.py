#!/usr/bin/env python3
"""
AWS IAM Identity Center Assignments Export Script

This script exports IAM Identity Center assignments for migration purposes.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

import boto3
from botocore.exceptions import ClientError


class IDCAssignmentsExporter:
    """Exports IAM Identity Center assignments."""

    def __init__(
        self,
        profile: str,
        region: str,
        export_dir: str,
        account_id: Optional[str] = None,
        permission_set: Optional[str] = None,
        include_inactive_users: bool = False,
        include_inactive_groups: bool = False,
        include_aws_managed: bool = False,
        debug: bool = False,
    ):
        """Initialize the exporter."""
        self.profile = profile
        self.region = region
        self.export_dir = Path(export_dir)
        self.filter_account_id = account_id
        self.filter_permission_set = permission_set
        self.include_inactive_users = include_inactive_users
        self.include_inactive_groups = include_inactive_groups
        self.include_aws_managed = include_aws_managed
        self.debug = debug

        # Initialize AWS clients
        session = boto3.Session(profile_name=profile, region_name=region)
        self.sso_admin = session.client("sso-admin")
        self.identity_store = session.client("identitystore")
        self.organizations = session.client("organizations")

        # Create export directories
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self.assignments_dir = self.export_dir / "assignments"
        self.assignments_dir.mkdir(exist_ok=True)

        # Cache for accounts and principals
        self.accounts_cache: Dict[str, str] = {}
        self.user_details_cache: Dict[str, Dict] = {}
        self.group_details_cache: Dict[str, Dict] = {}

    def get_sso_instance(self) -> tuple[str, str]:
        """Get SSO instance ARN and Identity Store ID."""
        response = self.sso_admin.list_instances()
        if not response.get("Instances"):
            raise ValueError("No IAM Identity Center instance found")

        instance = response["Instances"][0]
        return instance["InstanceArn"], instance["IdentityStoreId"]

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

    def export_accounts(self) -> Dict[str, str]:
        """Export all accounts and return account ID to name mapping."""
        print("\n=== Fetching Account Information ===")
        
        accounts = {}
        paginator = self.organizations.get_paginator("list_accounts")
        
        for page in paginator.paginate():
            for account in page["Accounts"]:
                accounts[account["Id"]] = account["Name"]

        # Save to file
        accounts_file = self.export_dir / "accounts.json"
        with open(accounts_file, "w") as f:
            json.dump({"Accounts": [{"Id": k, "Name": v} for k, v in accounts.items()]}, f, indent=2)

        self.accounts_cache = accounts
        print(f"Found {len(accounts)} accounts")
        return accounts

    def is_user_active(self, user_id: str, identity_store_id: str) -> bool:
        """Check if a specific user is active by examining detailed attributes."""
        if user_id in self.user_details_cache:
            user_details = self.user_details_cache[user_id]
        else:
            try:
                user_details = self.identity_store.describe_user(
                    IdentityStoreId=identity_store_id,
                    UserId=user_id
                )
                self.user_details_cache[user_id] = user_details
            except ClientError as e:
                if self.debug:
                    print(f"  Could not describe user {user_id}: {e}")
                return False

        # Get username for logging
        username = user_details.get("UserName", "")
        
        # Debug: Print full user details to understand the structure
        if self.debug:
            print(f"\n  DEBUG: Full user details for {username} ({user_id}):")
            print(f"    Raw response: {json.dumps(user_details, indent=4, default=str)}")
        
        # PRIMARY CHECK: UserStatus field (ENABLED or DISABLED)
        # This is the authoritative field according to AWS Identity Store API
        user_status = user_details.get("UserStatus")
        if user_status:
            if self.debug:
                print(f"  User {username} UserStatus: {user_status}")
            if user_status == "DISABLED":
                if self.debug:
                    print(f"  User {username} is DISABLED (UserStatus=DISABLED)")
                return False
            elif user_status == "ENABLED":
                if self.debug:
                    print(f"  User {username} is ENABLED (UserStatus=ENABLED)")
                # Continue with other checks even if enabled
        
        # SECONDARY CHECK: The 'Enabled' field (boolean) if present
        if "Enabled" in user_details:
            is_enabled = user_details["Enabled"]
            if not is_enabled:
                if self.debug:
                    print(f"  User {username} is DISABLED (Enabled=False)")
                return False
            else:
                if self.debug:
                    print(f"  User {username} is ENABLED (Enabled=True)")
        
        # TERTIARY CHECK: Check 'Active' flag if present
        if "Active" in user_details:
            is_active = user_details["Active"]
            if not is_active:
                if self.debug:
                    print(f"  User {username} marked as inactive (Active=False)")
                return False
        
        # Check legacy status field
        status = user_details.get("Status")
        if status:
            if self.debug:
                print(f"  User {username} Status: {status}")
            if status.lower() in ["inactive", "disabled", "suspended", "deprovisioned"]:
                if self.debug:
                    print(f"  User {username} has inactive Status: {status}")
                return False
        
        # Check if user has valid email addresses
        emails = user_details.get("Emails", [])
        has_valid_email = False
        for email in emails:
            if email.get("Value") and "@" in email.get("Value", ""):
                has_valid_email = True
                break
        
        if not has_valid_email and emails:  # Has email entries but none are valid
            if self.debug:
                print(f"  User {username} has no valid email addresses")
            return False
        
        # Check if user has essential name information
        name = user_details.get("Name", {})
        display_name = user_details.get("DisplayName", "")
        
        # If user has no meaningful name information, might be a test/inactive user
        if (not name.get("GivenName") and 
            not name.get("FamilyName") and 
            not display_name and 
            not username):
            if self.debug:
                print(f"  User {user_id} has no name information")
            return False
        
        # Check for test user patterns in username
        test_patterns = ["test-", "test_", "-test", "_test", "dummy", "sample", "temp"]
        username_lower = username.lower()
        for pattern in test_patterns:
            if pattern in username_lower:
                if self.debug:
                    print(f"  User {username} appears to be a test user (contains '{pattern}')")
                return False
        
        if self.debug:
            print(f"  User {username} passed all activity checks - considered ACTIVE")
        
        return True

    def is_group_active(self, group_id: str, identity_store_id: str) -> bool:
        """Check if a specific group is active."""
        if group_id in self.group_details_cache:
            group_details = self.group_details_cache[group_id]
        else:
            try:
                group_details = self.identity_store.describe_group(
                    IdentityStoreId=identity_store_id,
                    GroupId=group_id
                )
                self.group_details_cache[group_id] = group_details
            except ClientError as e:
                if self.debug:
                    print(f"  Could not describe group {group_id}: {e}")
                return False

        display_name = group_details.get("DisplayName", "")
        
        # Debug: Print full group details to understand the structure
        if self.debug:
            print(f"\n  DEBUG: Full group details for {display_name} ({group_id}):")
            print(f"    Raw response: {json.dumps(group_details, indent=4, default=str)}")
        
        # PRIMARY CHECK: The 'Enabled' field at the root level
        if "Enabled" in group_details:
            is_enabled = group_details["Enabled"]
            if not is_enabled:
                if self.debug:
                    print(f"  Group {display_name} is DISABLED (Enabled=False)")
                return False
            else:
                if self.debug:
                    print(f"  Group {display_name} is ENABLED (Enabled=True)")
        
        # SECONDARY CHECK: Check 'Active' flag if present
        if "Active" in group_details:
            is_active = group_details["Active"]
            if not is_active:
                if self.debug:
                    print(f"  Group {display_name} marked as inactive (Active=False)")
                return False
        
        # Check group status
        group_status = group_details.get("Status")
        if group_status:
            if self.debug:
                print(f"  Group {display_name} status: {group_status}")
            if group_status.lower() in ["inactive", "disabled", "suspended", "deprovisioned"]:
                if self.debug:
                    print(f"  Group {display_name} has inactive status: {group_status}")
                return False
        
        if self.debug:
            print(f"  Group {display_name} passed all activity checks - considered ACTIVE")
        
        return True

    def is_principal_active(
        self, 
        principal_type: str, 
        principal_id: str, 
        identity_store_id: str
    ) -> bool:
        """Check if a principal (user or group) is active."""
        if principal_type == "USER":
            if self.include_inactive_users:
                return True
            return self.is_user_active(principal_id, identity_store_id)
        elif principal_type == "GROUP":
            if self.include_inactive_groups:
                return True
            return self.is_group_active(principal_id, identity_store_id)
        return False

    def get_principal_name(
        self, 
        principal_type: str, 
        principal_id: str, 
        identity_store_id: str
    ) -> str:
        """Get principal name (user or group)."""
        try:
            if principal_type == "GROUP":
                response = self.identity_store.describe_group(
                    IdentityStoreId=identity_store_id,
                    GroupId=principal_id
                )
                return response.get("DisplayName", principal_id)
            else:
                response = self.identity_store.describe_user(
                    IdentityStoreId=identity_store_id,
                    UserId=principal_id
                )
                return response.get("UserName", principal_id)
        except ClientError:
            return principal_id

    def get_permission_sets(self, instance_arn: str) -> List[str]:
        """Get list of all permission set ARNs."""
        print("\n=== Fetching Permission Sets ===")
        
        permission_sets = []
        paginator = self.sso_admin.get_paginator("list_permission_sets")
        
        for page in paginator.paginate(InstanceArn=instance_arn):
            permission_sets.extend(page["PermissionSets"])

        print(f"Found {len(permission_sets)} permission sets")
        return permission_sets

    def get_permission_set_name(self, instance_arn: str, ps_arn: str) -> str:
        """Get permission set name from ARN."""
        try:
            response = self.sso_admin.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=ps_arn
            )
            return response["PermissionSet"]["Name"]
        except ClientError:
            return ps_arn

    def export_assignments(
        self, 
        instance_arn: str, 
        identity_store_id: str
    ):
        """Export assignments for all permission sets."""
        print("\n=== Exporting Assignments ===")

        # Get all permission sets
        permission_sets = self.get_permission_sets(instance_arn)

        # Dictionary to store assignments by account
        assignments_by_account: Dict[str, Dict[str, Dict]] = {}

        # Filter out AWS-managed permission sets if requested
        if not self.include_aws_managed:
            print("Filtering out AWS-managed permission sets...")
            filtered_ps = []
            for ps_arn in permission_sets:
                ps_name = self.get_permission_set_name(instance_arn, ps_arn)
                if not self.is_aws_managed_permission_set(instance_arn, ps_arn):
                    filtered_ps.append(ps_arn)
                else:
                    print(f"  Skipping AWS-managed permission set: {ps_name}")
            permission_sets = filtered_ps
            print(f"Filtered to {len(permission_sets)} custom permission sets")
        else:
            print("Including both custom and AWS-managed permission sets")

        # Filter permission sets if specified
        if self.filter_permission_set:
            filtered_ps = []
            for ps_arn in permission_sets:
                ps_name = self.get_permission_set_name(instance_arn, ps_arn)
                if ps_name == self.filter_permission_set:
                    filtered_ps.append(ps_arn)
            permission_sets = filtered_ps

        ps_count = len(permission_sets)
        ps_counter = 0

        for ps_arn in permission_sets:
            ps_counter += 1
            ps_name = self.get_permission_set_name(instance_arn, ps_arn)

            print(f"[{ps_counter}/{ps_count}] Processing assignments for: {ps_name}")

            # Get accounts where this permission set is provisioned
            accounts = []
            try:
                paginator = self.sso_admin.get_paginator("list_accounts_for_provisioned_permission_set")
                for page in paginator.paginate(
                    InstanceArn=instance_arn,
                    PermissionSetArn=ps_arn
                ):
                    accounts.extend(page.get("AccountIds", []))
            except ClientError as e:
                print(f"  Warning: Could not list accounts for {ps_name}: {e}")
                continue

            # Apply account filter if specified
            if self.filter_account_id:
                accounts = [acc for acc in accounts if acc == self.filter_account_id]

            # Process each account
            for account_id in accounts:
                account_name = self.accounts_cache.get(account_id, account_id)

                # Get assignments for this permission set and account
                try:
                    paginator = self.sso_admin.get_paginator("list_account_assignments")
                    for page in paginator.paginate(
                        InstanceArn=instance_arn,
                        AccountId=account_id,
                        PermissionSetArn=ps_arn
                    ):
                        for assignment in page.get("AccountAssignments", []):
                            principal_type = assignment["PrincipalType"]
                            principal_id = assignment["PrincipalId"]

                            # Check if principal is active
                            if not self.is_principal_active(principal_type, principal_id, identity_store_id):
                                if self.debug:
                                    principal_name_debug = self.get_principal_name(
                                        principal_type, principal_id, identity_store_id
                                    )
                                    print(f"    Skipping inactive {principal_type.lower()}: {principal_name_debug}")
                                continue

                            # Get principal name
                            principal_name = self.get_principal_name(
                                principal_type, 
                                principal_id, 
                                identity_store_id
                            )

                            # Create unique SID based on PermissionSet, PrincipalType, and PrincipalName
                            # (same format as shell script)
                            sid = f"{account_id}_{ps_name}_{principal_type}_{principal_name}"
                            sid = sid.replace(' ', '_').replace('/', '_').replace('@', '_').replace('.', '_')

                            # Target format: "AccountName:AccountId"
                            target = f"{account_name}:{account_id}"

                            # Initialize account assignments dict if needed
                            if account_id not in assignments_by_account:
                                assignments_by_account[account_id] = {}

                            # Check if this SID already exists for this account
                            if sid in assignments_by_account[account_id]:
                                # Add target to existing assignment (shouldn't happen in per-account files, but keeping logic)
                                if target not in assignments_by_account[account_id][sid]["Target"]:
                                    assignments_by_account[account_id][sid]["Target"].append(target)
                            else:
                                # Create new assignment entry (matching shell script format)
                                assignments_by_account[account_id][sid] = {
                                    "SID": sid,
                                    "Target": [target],
                                    "PrincipalType": principal_type,
                                    "PrincipalId": principal_name,
                                    "PermissionSetName": ps_name
                                }

                except ClientError as e:
                    print(f"  Warning: Could not list assignments for {ps_name} in account {account_id}: {e}")

        # Save assignments by account
        self._save_assignments_by_account(assignments_by_account)

    def _save_assignments_by_account(self, assignments_by_account: Dict[str, Dict[str, Dict]]):
        """Save assignments to separate files per account."""
        print("\n=== Saving Assignments ===")
        
        for account_id, assignments_dict in assignments_by_account.items():
            account_name = self.accounts_cache.get(account_id, account_id)
            assignment_file = self.assignments_dir / f"{account_id}-assignments.json"
            
            # Convert dict to list of assignments
            assignments_list = list(assignments_dict.values())
            
            # Output only the assignments array (matching shell script format)
            output_data = {
                "Assignments": assignments_list
            }
            
            with open(assignment_file, "w") as f:
                json.dump(output_data, f, indent=2)
            
            print(f"  Saved {len(assignments_list)} assignments for account {account_id} ({account_name})")

    def run(self):
        """Run the export process."""
        print("AWS IAM Identity Center Assignments Export Script")
        print("=" * 52)
        print(f"Using AWS Profile: {self.profile}")
        print(f"Region: {self.region}")
        print(f"Export Directory: {self.export_dir}")
        
        if self.filter_account_id:
            print(f"Filtering by Account ID: {self.filter_account_id}")
        if self.filter_permission_set:
            print(f"Filtering by Permission Set: {self.filter_permission_set}")
        print(f"Include Inactive Users: {self.include_inactive_users}")
        print(f"Include Inactive Groups: {self.include_inactive_groups}")
        print(f"Include AWS-managed Permission Sets: {self.include_aws_managed}")
        print(f"Debug Mode: {self.debug}")

        try:
            # Get SSO instance
            instance_arn, identity_store_id = self.get_sso_instance()
            print(f"\nInstance ARN: {instance_arn}")
            print(f"Identity Store ID: {identity_store_id}")

            # Export accounts
            self.export_accounts()

            # Export assignments
            self.export_assignments(instance_arn, identity_store_id)

            print("\n" + "=" * 52)
            print("Assignments export completed successfully!")
            print(f"Results saved to: {self.assignments_dir}")

        except Exception as e:
            print(f"\nError: {e}", file=sys.stderr)
            sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Export AWS IAM Identity Center assignments"
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
        "--account-id",
        help="Filter assignments by specific account ID"
    )
    parser.add_argument(
        "--permission-set",
        help="Filter by specific permission set name"
    )
    parser.add_argument(
        "--inactive-users",
        action="store_true",
        help="Include assignments for inactive users (default: False)"
    )
    parser.add_argument(
        "--inactive-groups",
        action="store_true",
        help="Include assignments for inactive groups (default: False)"
    )
    parser.add_argument(
        "--include-aws-managed",
        action="store_true",
        help="Include AWS-managed (predefined) permission sets in export (default: False, only custom permission sets)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output for user/group filtering"
    )

    args = parser.parse_args()

    exporter = IDCAssignmentsExporter(
        profile=args.profile,
        region=args.region,
        export_dir=args.export_dir,
        account_id=args.account_id,
        permission_set=args.permission_set,
        include_inactive_users=args.inactive_users,
        include_inactive_groups=args.inactive_groups,
        include_aws_managed=args.include_aws_managed,
        debug=args.debug,
    )

    exporter.run()


if __name__ == "__main__":
    main()
