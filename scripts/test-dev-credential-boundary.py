#!/usr/bin/env python3
"""Offline source guards; live IAM simulation and SSM acceptance are also required."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent


def source(name):
    return (ROOT / name).read_text()


def block(filename, kind, name, resource_type='[^\"]+'):
    match = re.search(
        r'^' + re.escape(kind) + r' "' + resource_type + r'" "' + re.escape(name)
        + r'" \{\n.*?^\}', source(filename), re.M | re.S,
    )
    if match is None:
        raise AssertionError(f'Missing {kind} {name} in {filename}')
    return match.group()


class DevCredentialBoundaryTests(unittest.TestCase):
    def test_dev_attachments_preserve_connectivity_during_cutover(self):
        for filename, name in [
            ('dev-instance-common.tf', 'dev_server_ssm'),
            ('nextjs-dev.tf', 'nextjs_dev_ssm'),
            ('dev-ebs.tf', 'dev_ebs_only_ssm'),
        ]:
            with self.subTest(role=name):
                attachment = block(filename, 'resource', name)
                self.assertIn('aws_iam_policy.ssm_managed_instance.arn', attachment)
                self.assertRegex(attachment, r'create_before_destroy\s*=\s*true')
                self.assertNotIn('AmazonSSMManagedInstanceCore', attachment)

    def test_shared_ssm_policy_retains_management_not_parameter_payloads(self):
        policy = source('ssm-managed-instance.tf')
        for action in ['ssm:UpdateInstanceInformation', 'ssm:GetDocument',
                       'ssmmessages:OpenControlChannel', 'ssmmessages:OpenDataChannel',
                       'ec2messages:GetMessages']:
            self.assertIn('"' + action + '"', policy)
        self.assertNotRegex(policy, r'"ssm:GetParameter[^\"]*"')

    def test_dev_cannot_send_commands_to_ami_builders(self):
        policy = block('dev-instance-common.tf', 'resource', 'dev_server', 'aws_iam_role_policy')
        self.assertNotIn('SSMSendCommandToAMIBuilders', policy)
        self.assertNotIn('ami-builder-temp', policy)
        self.assertIn('SSMSendCommandToRunners', policy)
        self.assertRegex(policy, r'"ssm:resourceTag/Role"\s*=\s*"github-runner"')
        self.assertIn('aws_ssm_parameter.dev_ssh_private_key.arn', policy)

    def test_nextjs_connector_metadata_is_exact_and_contains_no_payload(self):
        metadata = block('nextjs-dev.tf', 'data', 'nextjs_connector')
        self.assertIn('data "aws_secretsmanager_secret"', metadata)
        self.assertEqual(re.findall(r'^\s+"(cloudflare-[^\"]+)"', metadata, re.M), [
            'cloudflare-tunnel-credentials', 'cloudflare-dolphin-tunnel-credentials',
        ])
        self.assertNotIn('secret_version', metadata)
        self.assertNotIn('secret_string', metadata)

    def test_nextjs_policy_uses_only_connector_arns_and_existing_hop_key(self):
        policy = block('nextjs-dev.tf', 'resource', 'nextjs_dev', 'aws_iam_role_policy')
        self.assertEqual(policy.count('data.aws_secretsmanager_secret.nextjs_connector['), 2)
        for name in ['cloudflare-tunnel-credentials', 'cloudflare-dolphin-tunnel-credentials']:
            self.assertIn(f'data.aws_secretsmanager_secret.nextjs_connector["{name}"].arn', policy)
        self.assertIn('aws_secretsmanager_secret.dev_hop.arn', policy)
        self.assertNotIn('secret:cloudflare-', policy)
        self.assertNotIn('cloudflare-tunnel-token', policy)

    def test_required_public_ssh_and_access_service_token_remain(self):
        sg = block('nextjs-dev.tf', 'resource', 'nextjs_dev', 'aws_security_group')
        self.assertRegex(sg, r'from_port\s*=\s*22\b')
        self.assertRegex(sg, r'from_port\s*=\s*2022\b')
        self.assertIn('0.0.0.0/0', sg)
        cf = source('cloudflare.tf')
        self.assertIn('resource "cloudflare_zero_trust_access_service_token" "cc_games_automation"', cf)
        self.assertIn('token_id = cloudflare_zero_trust_access_service_token.cc_games_automation.id', cf)

if __name__ == '__main__':
    unittest.main(verbosity=2)
