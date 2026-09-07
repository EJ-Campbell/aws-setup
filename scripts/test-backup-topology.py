"""SDK-free regression checks for the reviewed fleet backup Terraform boundaries.

Run: python3 -S -B scripts/test-backup-topology.py
These check the checked-in topology, not live IAM authorization, delivery, or restore
success. They complement terraform validate and the controller's fake-client tests.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SECURITY = (ROOT / "backup-security.tf").read_text()
CANARY = (ROOT / "backup-restore-canary.tf").read_text()
DEV = (ROOT / "dev-instance-common.tf").read_text()
JUMPBOX = (ROOT / "jumpbox.tf").read_text()
WORKFLOW = (ROOT / ".github/workflows/lambda-tests.yml").read_text()
ALL_TF = "\n".join(path.read_text() for path in sorted(ROOT.glob("*.tf")))


def block(source, kind, *labels):
    """Read one fmt-style top-level block, without interpreting Terraform or IAM.

    Nested blocks close at nonzero indentation; root blocks close at column zero.
    Fail on duplicate/missing blocks instead of silently selecting the wrong one.
    """
    declaration = r"[ \t]+".join([re.escape(kind)] + [re.escape('"' + label + '"') for label in labels])
    matches = re.findall(r"^" + declaration + r"[ \t]*\{\n(.*?)^\}", source, re.M | re.S)
    if len(matches) != 1:
        raise AssertionError("Expected one block: " + " ".join((kind,) + labels))
    return matches[0]


def resource(kind, name, source=SECURITY):
    return block(source, "resource", kind, name)


def compact_list(source, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*=\s*compact\(\[(.*?)\]\)", source, re.S)
    if not match:
        raise AssertionError("Missing compact list: " + name)
    return match[1]


class BackupTopologyTests(unittest.TestCase):
    def test_recovery_account_and_region_are_explicit(self):
        self.assertRegex(SECURITY, r'backup_recovery_region\s*=\s*"us-east-1"')
        provider = block(SECURITY, "provider", "aws")
        self.assertRegex(provider, r'alias\s*=\s*"staging_dr"')
        self.assertRegex(provider, r"region\s*=\s*local\.backup_recovery_region")
        self.assertIn("aws_organizations_account.dev_staging[0].id", provider)
        self.assertIn(":role/OrganizationAccountAccessRole", provider)

    def test_new_lag_is_distinct_aws_owned_and_protected(self):
        old = resource("aws_backup_logically_air_gapped_vault", "staging_recovery")
        final = resource("aws_backup_logically_air_gapped_vault", "staging_recovery_dr")
        self.assertRegex(old, r"provider\s*=\s*aws\.staging\b")
        self.assertRegex(final, r"provider\s*=\s*aws\.staging_dr\b")
        for vault in (old, final):
            self.assertRegex(vault, r"min_retention_days\s*=\s*7\b")
            self.assertRegex(vault, r"max_retention_days\s*=\s*366\b")
            self.assertRegex(vault, r"prevent_destroy\s*=\s*true")
            self.assertNotIn("kms_key_arn", vault)

    def test_pending_vault_and_plans_never_expire_uncopied_data(self):
        vault = resource("aws_backup_vault", "processing")
        self.assertIn('"ejc3-backup-processing"', vault)
        self.assertRegex(vault, r"prevent_destroy\s*=\s*true")
        plan = resource("aws_backup_plan", "processing")
        self.assertIn('dev = "cron(0 6 * * ? *)"', plan)
        self.assertIn('jumpbox = "cron(0 5 * * ? *)"', plan)
        self.assertRegex(plan, r"target_vault_name\s*=\s*aws_backup_vault\.processing\.name")
        self.assertNotRegex(plan, r"\b(lifecycle|delete_after|cold_storage_after|copy_action)\s*[={]")
        self.assertIn('BackupPipeline = "fleet-processing-v2"', plan)

    def test_temporary_vaults_cannot_gain_a_retention_lock(self):
        locks = re.findall(r'^resource "aws_backup_vault_lock_configuration" "[^"]+"\s*\{\n(.*?)^\}', ALL_TF, re.M | re.S)
        for lock in locks:
            self.assertNotIn("aws_backup_vault.processing", lock)
            self.assertNotIn("aws_backup_vault.ejc3_backup_dr_cmk", lock)

    def test_cutover_routes_both_existing_selections_through_one_gate(self):
        # true is an intentional later rollout, not a permanent test failure.
        self.assertRegex(SECURITY, r"backup_recovery_cutover_enabled\s*=\s*(?:false|true)\b")
        for source, name, key, legacy in (
            (DEV, "dev_servers", "dev", "aws_backup_plan.dev_servers.id"),
            (JUMPBOX, "jumpbox", "jumpbox", "aws_backup_plan.jumpbox[0].id"),
        ):
            selection = resource("aws_backup_selection", name, source)
            expected = ('plan_id = local.backup_recovery_cutover_enabled ? '
                        'aws_backup_plan.processing["' + key + '"]' + '.id : ' + legacy)
            self.assertIn(re.sub(r"\s+", " ", expected), re.sub(r"\s+", " ", selection))
            self.assertNotIn('resources = ["*"]', re.sub(r"\s+", " ", selection))

    def test_controller_and_selections_protect_the_same_five_volumes(self):
        protected = compact_list(SECURITY, "backup_protected_volume_arns")
        dev = compact_list(resource("aws_backup_selection", "dev_servers", DEV), "resources")
        jumpbox = compact_list(resource("aws_backup_selection", "jumpbox", JUMPBOX), "resources")
        for name in ("arm_persistent_volume_arn", "x86_persistent_volume_arn", "nextjs_root_volume_arn"):
            self.assertIn("local." + name, protected)
            self.assertIn("local." + name, dev)
        for fragment in ("var.enable_jumpbox ? aws_ebs_volume.jumpbox_home[0].arn",
                         "var.enable_jumpbox_2 ?", "aws_instance.jumpbox_2[0].root_block_device[0].volume_id"):
            self.assertIn(fragment, protected)
            self.assertIn(fragment, jumpbox)

    def test_only_two_encrypted_roots_get_a_cmk_hop(self):
        hop = compact_list(SECURITY, "backup_cmk_hop_volume_arns")
        self.assertIn("local.nextjs_root_volume_arn", hop)
        self.assertIn("aws_instance.jumpbox_2[0].root_block_device[0].volume_id", hop)
        for unwanted in ("arm_persistent_volume_arn", "x86_persistent_volume_arn", "jumpbox_home"):
            self.assertNotIn(unwanted, hop)
        checkpoint = resource("aws_backup_vault", "ejc3_backup_dr_cmk")
        self.assertRegex(checkpoint, r"provider\s*=\s*aws\.dr\b")
        self.assertRegex(checkpoint, r"kms_key_arn\s*=\s*aws_kms_key\.backup_dr\.arn")
        self.assertRegex(resource("aws_kms_key", "backup_dr"), r"prevent_destroy\s*=\s*true")

    def test_cleanup_authority_is_gated_and_scoped_to_two_vault_policies(self):
        for policy_name, vault in (("processing_cleanup", "processing"),
                                   ("checkpoint_cleanup", "ejc3_backup_dr_cmk")):
            policy = resource("aws_backup_vault_policy", policy_name)
            self.assertRegex(policy, r"count\s*=\s*local\.backup_recovery_cutover_enabled\s*\?\s*1\s*:\s*0")
            self.assertRegex(policy, r"backup_vault_name\s*=\s*aws_backup_vault\." + vault + r"\.name")
            self.assertIn("AWS = aws_iam_role.backup_recovery.arn", policy)
            self.assertIn('Action = "backup:DeleteRecoveryPoint"', re.sub(r"\s+", " ", policy))
            self.assertNotIn('Action = "backup:*"', re.sub(r"\s+", " ", policy))
        processing = resource("aws_backup_vault_policy", "processing_cleanup")
        self.assertIn('"aws:ResourceTag/BackupPipeline" = "fleet-processing-v2"', processing)
        final = resource("aws_backup_vault_policy", "staging_recovery_dr")
        self.assertNotIn("DeleteRecoveryPoint", final)

    def test_controller_has_no_identity_deletion_or_retention_bypass(self):
        policy = resource("aws_iam_role_policy", "backup_recovery")
        self.assertNotIn("backup:DeleteRecoveryPoint", policy)
        denied = re.search(r'Effect\s*=\s*"Deny"\s+Action\s*=\s*\[(.*?)\]', policy, re.S).group(1)
        for action in ("ec2:DeleteSnapshot", "backup:UpdateRecoveryPointLifecycle",
                       "backup:DisassociateRecoveryPoint", "backup:TagResource", "backup:UntagResource",
                       "backup:PutBackupVaultAccessPolicy", "backup:DeleteBackupVaultAccessPolicy",
                       "backup:PutBackupVaultLockConfiguration", "backup:DeleteBackupVaultLockConfiguration"):
            self.assertIn('"' + action + '"', denied)
        self.assertIn('"iam:PassedToService" = "backup.amazonaws.com"', policy)
        self.assertIn("Resource = local.backup_service_role_arn", re.sub(r"\s+", " ", policy))

    def test_controller_uses_new_final_vault_and_optional_canary(self):
        function = resource("aws_lambda_function", "backup_recovery")
        for field, value in {
            "primary_region": "var.aws_region", "stage_region": "local.backup_recovery_region",
            "cleanup_enabled": "local.backup_recovery_cutover_enabled",
            "cmk_hop_volumes": "local.backup_cmk_hop_volume_arns",
            "processing_vault": "aws_backup_vault.processing.name",
            "stage_vault_arn": "aws_backup_logically_air_gapped_vault.staging_recovery_dr.arn",
            "restore_plan_arn": "aws_backup_restore_testing_plan.fleet_dr.arn",
            "volumes": "local.backup_protected_volume_arns",
        }.items():
            self.assertRegex(function, r"\b" + field + r"\s*=\s*" + re.escape(value))
        self.assertIn("try(aws_backup_restore_testing_plan.initial[0].arn, null)", function)
        self.assertIn("try(aws_backup_restore_testing_plan.initial[0].name, null)", function)
        self.assertNotRegex(function, r"aws_backup_logically_air_gapped_vault\.staging_recovery\.")

    def test_restore_resources_and_metadata_are_in_recovery_region(self):
        for source, plan_name, selection_name in ((SECURITY, "fleet_dr", "fleet_ebs_dr"),
                                                 (CANARY, "initial", "initial_ebs")):
            plan = resource("aws_backup_restore_testing_plan", plan_name, source)
            selection = resource("aws_backup_restore_testing_selection", selection_name, source)
            self.assertRegex(plan, r"provider\s*=\s*aws\.staging_dr\b")
            self.assertRegex(selection, r"provider\s*=\s*aws\.staging_dr\b")
            self.assertIn("aws_backup_logically_air_gapped_vault.staging_recovery_dr.arn", plan)
            self.assertRegex(selection, r'protected_resource_type\s*=\s*"EBS"')
            self.assertRegex(selection, r'protected_resource_arns\s*=\s*\["\*"\]')
            self.assertRegex(selection, r"validation_window_hours\s*=\s*2\b")
            self.assertIn("data.aws_availability_zones.backup_restore_staging_dr.names[0]", selection)
            self.assertRegex(selection, r'volumeType\s*=\s*"gp3"')
            self.assertNotRegex(selection, re.compile(r"^\s*encrypted\s*=", re.M))

    def test_restore_role_cannot_boot_attach_or_use_source_region(self):
        role = resource("aws_iam_role_policy", "backup_restore_test")
        observer = resource("aws_iam_role_policy", "backup_recovery_observer")
        self.assertRegex(role, r'Effect\s*=\s*"Deny"\s+Action\s*=\s*\["ec2:RunInstances",\s*"ec2:AttachVolume",\s*"iam:PassRole"\]')
        self.assertIn('"ec2:Encrypted" = "true"', role)
        self.assertIn('"ec2:VolumeType" = "gp3"', role)
        for policy in (role, observer):
            self.assertNotIn("var.aws_region", policy)
            self.assertIn('"aws:RequestedRegion" = local.backup_recovery_region', policy)
            self.assertIn('"aws:ResourceTag/awsbackup-restore-test"', policy)
        self.assertIn("aws_backup_restore_testing_plan.initial[*].arn", observer)
        for forbidden in ("backup:StartRestoreJob", "backup:StartCopyJob", "ec2:AttachVolume"):
            self.assertNotIn(forbidden, observer)

    def test_canary_is_explicit_minute_date_year_and_null_gated(self):
        self.assertRegex(CANARY, r'backup_initial_restore_at\s*=\s*(?:null|"[^"]+")')
        self.assertIn('formatdate("m h D M ? YYYY", local.backup_initial_restore_at)', CANARY)
        for kind, name in (("aws_backup_restore_testing_plan", "initial"),
                           ("aws_backup_restore_testing_selection", "initial_ebs")):
            self.assertRegex(resource(kind, name, CANARY), r"count\s*=\s*local\.backup_initial_restore_at\s*==\s*null\s*\?\s*0\s*:\s*1")
        plan = resource("aws_backup_restore_testing_plan", "initial", CANARY)
        self.assertIn("precondition", plan)
        self.assertIn(":00Z$", plan)
        self.assertNotRegex(plan, r"\b(?:timestamp|plantimestamp)\(")
        self.assertRegex(plan, r'schedule_expression_timezone\s*=\s*"Etc/UTC"')

    def test_periodic_scan_and_lambda_are_bounded(self):
        rule = resource("aws_cloudwatch_event_rule", "backup_reconcile")
        function = resource("aws_lambda_function", "backup_recovery")
        self.assertIn('schedule_expression = "rate(1 hour)"', re.sub(r"\s+", " ", rule))
        self.assertRegex(function, r"reserved_concurrent_executions\s*=\s*1\b")
        self.assertRegex(function, r"timeout\s*=\s*180\b")
        self.assertRegex(function, r"memory_size\s*=\s*256\b")
        self.assertIn("aws_organizations_organization.security", function)
        self.assertIn("aws_backup_global_settings.main", function)

    def test_recovery_events_use_east1_and_exact_forwarder_trust(self):
        for kind in ("aws_cloudwatch_event_rule", "aws_cloudwatch_event_target"):
            self.assertRegex(resource(kind, "backup_events_staging_dr"), r"provider\s*=\s*aws\.staging_dr\b")
        policy = resource("aws_cloudwatch_event_bus_policy", "backup_recovery")
        self.assertIn('"aws:PrincipalArn" = aws_iam_role.backup_event_forward_staging.arn', policy)
        self.assertIn('Action = "events:PutEvents"', re.sub(r"\s+", " ", policy))
        self.assertIn('state = ["COMPLETED", "FAILED", "EXPIRED", "ABORTED", "PARTIAL"]', SECURITY)
        self.assertIn('status = ["COMPLETED", "FAILED", "ABORTED"]', SECURITY)

    def test_packaged_controller_and_test_workflow_are_credential_free(self):
        archive = block(SECURITY, "data", "archive_file", "backup_recovery")
        self.assertIn('file("${path.module}/scripts/backup-recovery.py")', archive)
        self.assertIn("source_code_hash", resource("aws_lambda_function", "backup_recovery"))
        self.assertIn("python3 -S -B scripts/test-backup-topology.py", WORKFLOW)
        self.assertIn("persist-credentials: false", WORKFLOW)
        self.assertNotIn("id-token: write", WORKFLOW)
        self.assertNotIn("configure-aws-credentials", WORKFLOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
