#!/usr/bin/env python3
"""Plan/apply repository-scoped OIDC signing with an EXISTING Azure application.

Credentials remain GitHub organization variables/secrets. This helper never
creates an application, client secret or paid signing resource, and never
changes an organization OIDC template. Default execution is read-only.
"""
import argparse
import json
import re
import subprocess
import sys
import uuid

SIGNER_ROLE = '2837e146-70d7-4cfd-ad55-7efa6464f958'
CLAIM_KEYS = ['repository_owner_id', 'repository_id', 'context']
ISSUER = 'https://token.actions.githubusercontent.com'
AUDIENCES = ['api://AzureADTokenExchange']
BRANCH_RULES = {('branch', 'main'), ('tag', 'v*')}


def run(args, payload=None):
    result = subprocess.run(args, input=None if payload is None else json.dumps(payload),
                            capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f'{args[0]} command failed: {result.stderr.strip()}')
    return json.loads(result.stdout) if result.stdout.strip() else None


def github(method, endpoint, payload=None):
    args = ['gh', 'api', '--method', method, endpoint]
    if payload is not None:
        args += ['--input', '-']
    return run(args, payload)


def exact_subject(repo, environment):
    owner_id, repo_id = repo.get('owner', {}).get('id'), repo.get('id')
    if type(owner_id) is not int or owner_id <= 0 or type(repo_id) is not int or repo_id <= 0:
        raise ValueError('GitHub must return positive immutable owner and repository IDs')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', environment):
        raise ValueError('environment must contain only letters, digits, dot, hyphen or underscore')
    return f'repository_owner_id:{owner_id}:repository_id:{repo_id}:environment:{environment}'


def plan(args):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        raise ValueError('repository must be canonical OWNER/REPO')
    for value in (args.tenant_id, args.subscription_id, args.application_id):
        uuid.UUID(value)
    for value in (args.resource_group, args.account, args.profile, args.credential_name):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', value):
            raise ValueError('resource and credential names contain unsupported characters')
    if not re.fullmatch(r'https://[a-z0-9]+\.codesigning\.azure\.net/', args.endpoint):
        raise ValueError('endpoint must be the account regional HTTPS codesigning.azure.net endpoint')
    repo = github('GET', f'repos/{args.repository}')
    if repo.get('full_name') != args.repository:
        raise ValueError('use the canonical repository full_name returned by GitHub')
    current = github('GET', f'repos/{args.repository}/actions/oidc/customization/sub')
    scope = (f'/subscriptions/{args.subscription_id}/resourceGroups/{args.resource_group}'
             f'/providers/Microsoft.CodeSigning/codeSigningAccounts/{args.account}/certificateProfiles/{args.profile}')
    return {'repository': args.repository, 'environment': args.environment,
            'existingApplicationID': args.application_id, 'tenantID': args.tenant_id,
            'subscriptionID': args.subscription_id, 'profileScope': scope, 'roleID': SIGNER_ROLE,
            'currentRepositoryOIDC': current,
            'repositoryOIDC': {'use_default': False, 'include_claim_keys': CLAIM_KEYS},
            'federatedCredential': {'name': args.credential_name, 'issuer': ISSUER,
                                   'audiences': AUDIENCES, 'subject': exact_subject(repo, args.environment)},
            'environmentPolicy': {'branches': ['main'], 'tags': ['v*'], 'addRequiredReviewers': False},
            'organizationVariables': {'AZURE_CLIENT_ID': args.application_id, 'AZURE_TENANT_ID': args.tenant_id,
                'AZURE_SUBSCRIPTION_ID': args.subscription_id, 'AZURE_SIGNING_ENDPOINT': args.endpoint,
                'AZURE_SIGNING_ACCOUNT': args.account, 'AZURE_SIGNING_PROFILE': args.profile},
            'organizationVariablesAction': 'unchanged; configure in organization settings',
            'replaceSubjectOnlyIfExactMatch': args.replace_subject}


def credential_operation(existing, desired, replace_subject):
    matches = [item for item in existing if item.get('name') == desired['name']]
    if len(matches) > 1:
        raise ValueError('duplicate named federated credentials')
    if not matches:
        return 'create', None
    item = matches[0]
    if item.get('issuer') != ISSUER or item.get('audiences') != AUDIENCES:
        raise ValueError('refusing to modify a credential with another issuer/audience')
    if item.get('subject') == desired['subject']:
        return 'unchanged', item['id']
    if not replace_subject or item.get('subject') != replace_subject:
        raise ValueError('existing named credential differs; provide its exact old --replace-subject only for an intended migration')
    return 'update', item['id']


def ensure_environment(repository, environment):
    endpoint = f'repos/{repository}/environments/{environment}'
    environments = github('GET', f'repos/{repository}/environments?per_page=100')['environments']
    existing = next((item for item in environments if item['name'] == environment), None)
    expected_policy = {'protected_branches': False, 'custom_branch_policies': True}
    if existing is None or existing.get('deployment_branch_policy') != expected_policy:
        github('PUT', endpoint, {'deployment_branch_policy': expected_policy})
    rules = github('GET', endpoint + '/deployment-branch-policies')['branch_policies']
    actual = {(item['type'], item['name']) for item in rules}
    for kind, name in sorted(BRANCH_RULES - actual):
        github('POST', endpoint + '/deployment-branch-policies', {'type': kind, 'name': name})
    # Enforce the explicitly reviewed main/v* scope, without adding reviewers.
    for item in rules:
        if (item['type'], item['name']) not in BRANCH_RULES:
            github('DELETE', endpoint + '/deployment-branch-policies/' + str(item['id']))


def apply(args, config):
    # All identity/trust checks precede mutations, including checking whether a
    # named FIC is ours to migrate. Do not inspect or print an OIDC JWT.
    current_plan = plan(args)
    if current_plan['federatedCredential'] != config['federatedCredential']:
        raise ValueError('repository identity changed after planning; regenerate the plan')
    account = run(['az', 'account', 'show', '--output', 'json'])
    if account['tenantId'] != args.tenant_id or account['id'] != args.subscription_id:
        raise ValueError('Azure CLI must select the specified tenant and subscription')
    application = run(['az', 'ad', 'app', 'show', '--id', args.application_id])
    if application.get('appId') != args.application_id:
        raise ValueError('existing application ID does not match')
    principals = run(['az', 'ad', 'sp', 'list', '--filter', f"appId eq '{args.application_id}'"])
    if (len(principals) != 1 or principals[0].get('appOwnerOrganizationId') != args.tenant_id or
            principals[0].get('accountEnabled') is not True):
        raise ValueError('expected one enabled service principal belonging to the specified tenant')
    principal = principals[0]
    scope = config['profileScope']
    resource = run(['az', 'rest', '--method', 'get', '--url',
                    'https://management.azure.com' + scope + '?api-version=2025-10-13'])
    if resource.get('properties', {}).get('status') != 'Active' or resource['properties'].get('profileType') != 'PublicTrust':
        raise ValueError('existing profile must be Active and PublicTrust')
    credentials = run(['az', 'ad', 'app', 'federated-credential', 'list', '--id', application['id']])
    operation, credential_id = credential_operation(credentials, config['federatedCredential'], args.replace_subject)
    assignments = run(['az', 'role', 'assignment', 'list', '--assignee', principal['id'], '--all'])
    has_role = any(item['scope'].lower() == scope.lower() and
                   item['roleDefinitionId'].rsplit('/', 1)[-1] == SIGNER_ROLE for item in assignments)
    ensure_environment(args.repository, args.environment)
    if operation in ('create', 'update'):
        command = ['az', 'ad', 'app', 'federated-credential', operation, '--id', application['id']]
        if operation == 'update':
            command += ['--federated-credential-id', credential_id]
        run(command + ['--parameters', json.dumps(config['federatedCredential'])])
    github('PUT', f'repos/{args.repository}/actions/oidc/customization/sub', config['repositoryOIDC'])
    if not has_role:
        assignment = str(uuid.uuid5(uuid.NAMESPACE_URL, scope.lower() + ':' + principal['id'] + ':' + SIGNER_ROLE))
        run(['az', 'role', 'assignment', 'create', '--name', assignment, '--assignee-object-id', principal['id'],
             '--assignee-principal-type', 'ServicePrincipal', '--role', SIGNER_ROLE, '--scope', scope])
    # Read back the trust and constraints. Org variables and org OIDC are untouched.
    oidc = github('GET', f'repos/{args.repository}/actions/oidc/customization/sub')
    if oidc.get('use_default') is not False or oidc.get('include_claim_keys') != CLAIM_KEYS:
        raise ValueError('GitHub repository OIDC read-back does not match')
    credentials = run(['az', 'ad', 'app', 'federated-credential', 'list', '--id', application['id']])
    if credential_operation(credentials, config['federatedCredential'], '')[0] != 'unchanged':
        raise ValueError('Azure federated credential read-back does not match')
    endpoint = f'repos/{args.repository}/environments/{args.environment}'
    rules = github('GET', endpoint + '/deployment-branch-policies')['branch_policies']
    if {(item['type'], item['name']) for item in rules} != BRANCH_RULES:
        raise ValueError('environment deployment policy read-back does not match main/v*')
    print('Configured exact repository/environment OIDC trust. Organization credentials and other repositories are unchanged.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant-id', required=True)
    parser.add_argument('--subscription-id', required=True)
    parser.add_argument('--application-id', required=True)
    parser.add_argument('--resource-group', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--repository', default='Bit-Precise/agentd')
    parser.add_argument('--environment', default='release-signing')
    parser.add_argument('--credential-name', default='credential-github')
    parser.add_argument('--replace-subject', default='')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        config = plan(args)
        print(json.dumps(config, indent=2))
        if args.apply:
            apply(args, config)
        else:
            print('DRY RUN: GitHub metadata read only; no writes. Review before adding --apply.')
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f'configure signing: {error}\n')


if __name__ == '__main__':
    main()
