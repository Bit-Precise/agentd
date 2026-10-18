#!/usr/bin/env python3
"""Review or apply dedicated GitHub OIDC access to an EXISTING signing profile.

Default is a local dry run. --apply creates IAM identities/role assignment and
configures GitHub variables; it does not create paid Azure signing resources.
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


def plan(args):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        raise ValueError('repository must be OWNER/REPO')
    for value in (args.tenant_id, args.subscription_id):
        uuid.UUID(value)
    for value in (args.resource_group, args.account, args.profile, args.environment, args.application_name):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', value):
            raise ValueError('resource and identity names must contain only letters, digits, dot, hyphen or underscore')
    if not re.fullmatch(r'https://[a-z0-9]+\.codesigning\.azure\.net/', args.endpoint):
        raise ValueError('endpoint must be the existing account HTTPS codesigning.azure.net regional endpoint')
    scope = (f'/subscriptions/{args.subscription_id}/resourceGroups/{args.resource_group}'
             f'/providers/Microsoft.CodeSigning/codeSigningAccounts/{args.account}/certificateProfiles/{args.profile}')
    federated = {'name': 'github-agentd-release-signing',
                 'issuer': 'https://token.actions.githubusercontent.com',
                 'subject': f'repo:{args.repository}:environment:{args.environment}',
                 'audiences': ['api://AzureADTokenExchange']}
    return {'applicationName': args.application_name, 'existingApplicationID': args.application_id,
            'tenantID': args.tenant_id, 'subscriptionID': args.subscription_id,
            'role': 'Artifact Signing Certificate Profile Signer', 'roleID': SIGNER_ROLE,
            'scope': scope, 'federatedCredential': federated,
            'githubEnvironment': args.environment, 'githubRepository': args.repository,
            'githubVariables': {'AZURE_CLIENT_ID': args.application_id or '<new dedicated application ID>',
                                'AZURE_TENANT_ID': args.tenant_id,
                                'AZURE_SUBSCRIPTION_ID': args.subscription_id,
                                'AZURE_SIGNING_ENDPOINT': args.endpoint,
                                'AZURE_SIGNING_ACCOUNT': args.account, 'AZURE_SIGNING_PROFILE': args.profile},
            'environmentPolicy': {'noRequiredReviewersAdded': True,
                                  'deploymentBranches': ['main'], 'deploymentTags': ['v*']}}


def apply(args, config):
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
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        config = plan(args)
        print(json.dumps(config, indent=2))
        if args.apply:
            apply(args, config)
        else:
            print('DRY RUN: no Azure or GitHub reads/writes performed. Review before adding --apply.')
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'configure signing: {error}\n')


if __name__ == '__main__':
    main()
