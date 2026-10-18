#!/usr/bin/env python3
"""Review or apply dedicated GitHub OIDC access to an EXISTING signing profile.

Default is a dry run: supply an explicit --subject-prefix for an offline plan,
or --discover-subject to read the actual GitHub OIDC configuration. --apply
revalidates that configuration before any IAM write. It creates IAM identities/
role assignment and GitHub variables, never paid Azure signing resources.
"""
import argparse
import json
import re
import subprocess
import sys
import uuid

SIGNER_ROLE = '2837e146-70d7-4cfd-ad55-7efa6464f958'


def run(args):
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def validate_subject_prefix(prefix, repository):
    # Do not accept a full subject, wildcard, or a custom claim template here.
    # Either both repository/owner immutable IDs are present or neither is.
    name = r'[A-Za-z0-9_.-]+'
    legacy = re.fullmatch(rf'repo:({name})/({name})', prefix)
    immutable = re.fullmatch(rf'repo:({name})@[1-9][0-9]*/({name})@[1-9][0-9]*', prefix)
    match = immutable or legacy
    if match is None or '/'.join(match.groups()) != repository:
        raise ValueError('subject prefix must be the exact default GitHub prefix for the canonical OWNER/REPO')
    return prefix


def discover_subject_prefix(repository):
    """Read configuration/IDs, never request or print an OIDC JWT."""
    config = run(['gh', 'api', f'repos/{repository}/actions/oidc/customization/sub'])
    if config.get('use_default') is not True:
        raise ValueError('repository uses a custom OIDC subject template; this per-repository helper only supports the default template')
    immutable = config.get('use_immutable_subject')
    prefix = config.get('sub_claim_prefix')
    if type(immutable) is not bool or not isinstance(prefix, str):
        raise ValueError('GitHub did not return an explicit immutable-subject setting and sub_claim_prefix; refusing to guess the OIDC subject')
    repo = run(['gh', 'api', f'repos/{repository}'])
    if repo.get('full_name') != repository:
        raise ValueError('use the canonical repository full_name returned by GitHub')
    expected = 'repo:' + repository
    if immutable:
        owner_id, repo_id = repo.get('owner', {}).get('id'), repo.get('id')
        if type(owner_id) is not int or owner_id <= 0 or type(repo_id) is not int or repo_id <= 0:
            raise ValueError('GitHub did not return valid immutable owner/repository IDs')
        owner, name = repository.split('/')
        expected = f'repo:{owner}@{owner_id}/{name}@{repo_id}'
    if prefix != expected:
        raise ValueError('GitHub OIDC prefix disagrees with its template setting or repository IDs; refusing to configure trust')
    return validate_subject_prefix(prefix, repository)


def plan(args):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        raise ValueError('repository must be OWNER/REPO')
    for value in (args.tenant_id, args.subscription_id):
        uuid.UUID(value)
    if args.application_id: uuid.UUID(args.application_id)
    for value in (args.resource_group, args.account, args.profile, args.environment, args.application_name):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', value):
            raise ValueError('resource and identity names must contain only letters, digits, dot, hyphen or underscore')
    if not re.fullmatch(r'https://[a-z0-9]+\.codesigning\.azure\.net/', args.endpoint):
        raise ValueError('endpoint must be the existing account HTTPS codesigning.azure.net regional endpoint')
    if args.discover_subject:
        prefix = discover_subject_prefix(args.repository)
    elif args.subject_prefix:
        prefix = validate_subject_prefix(args.subject_prefix, args.repository)
    else:
        raise ValueError('supply --subject-prefix for an offline dry run or --discover-subject for read-only discovery')
    scope = (f'/subscriptions/{args.subscription_id}/resourceGroups/{args.resource_group}'
             f'/providers/Microsoft.CodeSigning/codeSigningAccounts/{args.account}/certificateProfiles/{args.profile}')
    federated = {'name': 'github-agentd-release-signing',
                 'issuer': 'https://token.actions.githubusercontent.com',
                 'subject': f'{prefix}:environment:{args.environment}',
                 'audiences': ['api://AzureADTokenExchange']}
    return {'applicationName': args.application_name, 'existingApplicationID': args.application_id,
            'tenantID': args.tenant_id, 'subscriptionID': args.subscription_id,
            'role': 'Artifact Signing Certificate Profile Signer', 'roleID': SIGNER_ROLE,
            'scope': scope, 'federatedCredential': federated,
            'githubSubjectPrefix': prefix,
            'githubEnvironment': args.environment, 'githubRepository': args.repository,
            'githubVariables': {'AZURE_CLIENT_ID': args.application_id or '<new dedicated application ID>',
                                'AZURE_TENANT_ID': args.tenant_id,
                                'AZURE_SUBSCRIPTION_ID': args.subscription_id,
                                'AZURE_SIGNING_ENDPOINT': args.endpoint,
                                'AZURE_SIGNING_ACCOUNT': args.account, 'AZURE_SIGNING_PROFILE': args.profile},
            'environmentPolicy': {'noRequiredReviewersAdded': True,
                                  'deploymentBranches': ['main'], 'deploymentTags': ['v*']}}


def apply(args, config):
    # Recheck immediately before *any* Azure identity/role or GitHub write. An
    # offline plan is not evidence that the live repository uses that subject.
    prefix = discover_subject_prefix(args.repository)
    expected_subject = f'{prefix}:environment:{args.environment}'
    if config['githubSubjectPrefix'] != prefix or config['federatedCredential']['subject'] != expected_subject:
        raise ValueError('planned subject does not match current GitHub OIDC configuration; regenerate and review the plan')
    account = run(['az', 'account', 'show', '--output', 'json'])
    if account['tenantId'] != args.tenant_id or account['id'] != args.subscription_id:
        raise ValueError('Azure CLI must already select the specified tenant and subscription')
    resource = run(['az', 'rest', '--method', 'get', '--url',
                    'https://management.azure.com' + config['scope'] + '?api-version=2025-10-13'])
    if resource.get('properties', {}).get('status') != 'Active' or resource['properties'].get('profileType') != 'PublicTrust':
        raise ValueError('existing profile must be Active and PublicTrust')
    if args.application_id:
        application = run(['az', 'ad', 'app', 'show', '--id', args.application_id])
        if application['displayName'] != args.application_name:
            raise ValueError('explicit application ID does not match the dedicated application name')
    else:
        existing = run(['az', 'ad', 'app', 'list', '--filter', f"displayName eq '{args.application_name}'"])
        if existing:
            raise ValueError('application name already exists; inspect it and supply --application-id to resume explicitly')
        application = run(['az', 'ad', 'app', 'create', '--display-name', args.application_name,
                           '--sign-in-audience', 'AzureADMyOrg'])
    app_id = application['appId']
    print('Dedicated application ID:', app_id, flush=True)
    principals = run(['az', 'ad', 'sp', 'list', '--filter', f"appId eq '{app_id}'"])
    principal = principals[0] if len(principals) == 1 else run(['az', 'ad', 'sp', 'create', '--id', app_id])
    federated = run(['az', 'ad', 'app', 'federated-credential', 'list', '--id', application['id']])
    matching = [item for item in federated if item['name'] == config['federatedCredential']['name']]
    if matching and any(matching[0].get(key) != value for key, value in config['federatedCredential'].items()):
        raise ValueError('existing named federated credential differs; refusing to replace its trust policy')
    if not matching:
        run(['az', 'ad', 'app', 'federated-credential', 'create', '--id', application['id'],
             '--parameters', json.dumps(config['federatedCredential'])])
    # A deterministic assignment ID makes retrying after a partial failure safe.
    assignment = str(uuid.uuid5(uuid.NAMESPACE_URL, config['scope'].lower() + ':' + principal['id'] + ':' + SIGNER_ROLE))
    run(['az', 'role', 'assignment', 'create', '--name', assignment, '--assignee-object-id', principal['id'],
         '--assignee-principal-type', 'ServicePrincipal', '--role', SIGNER_ROLE, '--scope', config['scope']])
    # PUT only when absent. Preserve any operator-managed protection/reviewer rules.
    endpoint = f'repos/{args.repository}/environments/{args.environment}'
    existing_environment = subprocess.run(['gh', 'api', endpoint], capture_output=True, text=True)
    if existing_environment.returncode:
        if '(HTTP 404)' not in existing_environment.stderr:
            raise ValueError('could not inspect GitHub environment; refusing to overwrite configuration')
        subprocess.run(['gh', 'api', '--method', 'PUT', endpoint, '--input', '-'], input=json.dumps({
            'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}
        }), text=True, check=True, stdout=subprocess.DEVNULL)
        for kind, name in (('branch', 'main'), ('tag', 'v*')):
            run(['gh', 'api', '--method', 'POST', endpoint + '/deployment-branch-policies',
                 '-f', 'name=' + name, '-f', 'type=' + kind])
    config['githubVariables']['AZURE_CLIENT_ID'] = app_id
    for name, value in config['githubVariables'].items():
        subprocess.run(['gh', 'variable', 'set', name, '--repo', args.repository,
                        '--env', args.environment, '--body', value], check=True)
    print('Configured dedicated OIDC signing access. No client secret was created.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant-id', required=True)
    parser.add_argument('--subscription-id', required=True)
    parser.add_argument('--resource-group', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--repository', default='Bit-Precise/agentd')
    parser.add_argument('--environment', default='release-signing')
    parser.add_argument('--application-name', default='agentd-release-signing')
    parser.add_argument('--application-id', default='')
    subject = parser.add_mutually_exclusive_group(required=True)
    subject.add_argument('--subject-prefix', help='exact default GitHub sub_claim_prefix for an offline dry run')
    subject.add_argument('--discover-subject', action='store_true', help='read GitHub OIDC configuration and repository IDs; no writes')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        config = plan(args)
        print(json.dumps(config, indent=2))
        if args.apply:
            apply(args, config)
        else:
            access = 'GitHub configuration read only; no writes' if args.discover_subject else 'no Azure or GitHub reads/writes performed'
            print(f'DRY RUN: {access}. Review before adding --apply.')
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'configure signing: {error}\n')


if __name__ == '__main__':
    main()
