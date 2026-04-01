# AWS IAM Identity Center Export Scripts

This directory contains Python scripts for exporting AWS IAM Identity Center (IDC) configurations for migration and analysis purposes.

## Scripts Overview

### 1. `export_idc_assignments.py`
Exports IAM Identity Center assignments (user/group to permission set to account mappings) with intelligent filtering for active principals. By default, filters out inactive users and groups, and excludes AWS-managed permission sets to focus on custom configurations.

### 2. `export_idc_psets.py`
Exports IAM Identity Center permission set definitions including managed policies, customer managed policies, and inline policies. Includes built-in policy validation using AWS Access Analyzer to detect and fix invalid actions automatically.

## Prerequisites

- Python 3.7+
- AWS CLI configured with appropriate credentials
- Required Python packages:
  ```bash
  pip install boto3
  ```
- Required AWS permissions:
  - `sso:ListInstances`
  - `sso-admin:*` (for permission sets and assignments)
  - `identitystore:*` (for user/group details)
  - `organizations:ListAccounts` (for account information)
  - `access-analyzer:ValidatePolicy` (for policy validation in export_idc_psets.py)

## Usage

### Export Assignments

Basic usage to export all assignments for active users/groups with custom permission sets:

```bash
python export_idc_assignments.py \
  --profile my-aws-profile \
  --region us-east-1 \
  --export-dir ./migration
```

Export assignments for a specific account:

```bash
python export_idc_assignments.py \
  --profile my-aws-profile \
  --account-id 123456789012 \
  --export-dir ./migration
```

Export assignments for a specific permission set:

```bash
python export_idc_assignments.py \
  --profile my-aws-profile \
  --permission-set "AWSAdministratorAccess" \
  --export-dir ./migration
```

Include inactive users and groups:

```bash
python export_idc_assignments.py \
  --profile my-aws-profile \
  --inactive-users \
  --inactive-groups \
  --export-dir ./migration
```

Include AWS-managed permission sets:

```bash
python export_idc_assignments.py \
  --profile my-aws-profile \
  --include-aws-managed \
  --export-dir ./migration
```

Enable debug mode to see detailed filtering decisions:

```bash
python export_idc_assignments.py \
  --profile my-aws-profile \
  --debug \
  --export-dir ./migration
```

### Export Permission Sets

Basic usage to export all custom permission sets:

```bash
python export_idc_psets.py \
  --profile my-aws-profile \
  --region us-east-1 \
  --export-dir ./migration/pset_definitions
```

Export a specific permission set:

```bash
python export_idc_psets.py \
  --profile my-aws-profile \
  --permission-set "MyCustomPermissionSet" \
  --export-dir ./migration/pset_definitions
```

Include AWS-managed permission sets:

```bash
python export_idc_psets.py \
  --profile my-aws-profile \
  --include-aws-managed \
  --export-dir ./migration/pset_definitions
```

Export only permission sets with assignments for a specific account:

```bash
python export_idc_psets.py \
  --profile my-aws-profile \
  --account-id 123456789012 \
  --export-dir ./migration/pset_definitions
```

## Command Line Options

### `export_idc_assignments.py` Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--profile` | AWS profile to use | `AWS_PROFILE` env var or `default` |
| `--region` | AWS region where IAM Identity Center is configured | `AWS_DEFAULT_REGION` env var or `us-east-1` |
| `--export-dir` | Directory where export files will be saved | `./migration` |
| `--account-id` | Filter assignments by specific AWS account ID | None (exports all accounts) |
| `--permission-set` | Filter by specific permission set name | None (exports all permission sets) |
| `--inactive-users` | Include assignments for inactive users | False (excludes inactive users) |
| `--inactive-groups` | Include assignments for inactive groups | False (excludes inactive groups) |
| `--include-aws-managed` | Include AWS-managed (predefined) permission sets | False (only custom permission sets) |
| `--debug` | Enable debug output for user/group filtering decisions | False |

### `export_idc_psets.py` Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--profile` | AWS profile to use | `AWS_PROFILE` env var or `default` |
| `--region` | AWS region where IAM Identity Center is configured | `AWS_DEFAULT_REGION` env var or `us-east-1` |
| `--export-dir` | Directory where export files will be saved | `./migration/pset_definitions` |
| `--permission-set` | Filter by specific permission set name | None (exports all permission sets) |
| `--include-aws-managed` | Include AWS-managed (predefined) permission sets | False (only custom permission sets) |
| `--account-id` | Filter to permission sets with assignments for specified account | None (exports all permission sets) |

## Output Structure

### Assignment Export (`export_idc_assignments.py`)

```
./migration/
├── accounts.json                    # All organization accounts
└── assignments/
    ├── 123456789012-assignments.json  # Assignments for account 123456789012
    ├── 234567890123-assignments.json  # Assignments for account 234567890123
    └── ...
```

**accounts.json format:**
```json
{
  "Accounts": [
    {
      "Id": "123456789012",
      "Name": "Production"
    },
    {
      "Id": "234567890123",
      "Name": "Development"
    }
  ]
}
```

**Assignment file format (e.g., 123456789012-assignments.json):**
```json
{
  "Assignments": [
    {
      "SID": "123456789012_AWSAdministratorAccess_USER_john_doe",
      "Target": ["Production:123456789012"],
      "PrincipalType": "USER",
      "PrincipalId": "john.doe",
      "PermissionSetName": "AWSAdministratorAccess"
    },
    {
      "SID": "123456789012_AWSReadOnlyAccess_GROUP_Developers",
      "Target": ["Production:123456789012"],
      "PrincipalType": "GROUP",
      "PrincipalId": "Developers",
      "PermissionSetName": "AWSReadOnlyAccess"
    }
  ]
}
```

### Permission Set Export (`export_idc_psets.py`)

```
./migration/pset_definitions/
├── permission_sets.txt              # List of all permission set ARNs
├── ps_AWSAdministratorAccess.json   # Permission set definition
├── ps_AWSReadOnlyAccess.json        # Permission set definition
├── ps_MyCustomPermissionSet.json    # Permission set definition
└── ...
```

**Permission set file format:**
```json
{
  "Name": "MyCustomPermissionSet",
  "Description": "Custom permission set for developers",
  "SessionDuration": "PT8H",
  "RelayState": "",
  "ManagedPolicies": [
    "arn:aws:iam::aws:policy/ReadOnlyAccess"
  ],
  "CustomerManagedPolicies": [
    "MyCustomPolicy"
  ],
  "PermissionBoundary": {},
  "CustomPolicy": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        "Resource": "*"
      }
    ]
  }
}
```

## Troubleshooting

### Common Issues

1. **No IAM Identity Center instance found**
   - Ensure IDC is enabled in the specified region
   - Verify AWS credentials have access to the management account
   - Check that you're using the correct region parameter

2. **Permission denied errors**
   - Check AWS credentials have required permissions (see Prerequisites)
   - Ensure you're using the correct AWS profile
   - Verify the profile has access to the management account

3. **Empty export results**
   - Verify there are actual assignments/permission sets configured
   - Check if filtering options are too restrictive
   - For permission sets: by default only custom permission sets are exported (use `--include-aws-managed` to include predefined ones)
   - For assignments: by default inactive users/groups are excluded (use `--inactive-users` and `--inactive-groups` to include them)

4. **Policy validation errors**
   - The script will automatically attempt to fix invalid actions
   - If validation fails repeatedly, check the inline policy syntax
   - Review Access Analyzer findings in the output for guidance

5. **Missing assignments for expected users/groups**
   - Enable debug mode with `--debug` to see why principals are being filtered
   - Check if users/groups are marked as inactive in Identity Store
   - Use `--inactive-users` or `--inactive-groups` to include them

6. **Script runs slowly**
   - Large organizations with many accounts/permission sets will take longer
   - Consider using `--account-id` or `--permission-set` filters to reduce scope
   - The script uses pagination and caching to optimize performance