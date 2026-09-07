"""Focused read-only unit checks for copy and restore safety decisions."""
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone

class ClientError(Exception):
    """Only the error response shape consumed by production cleanup is needed."""
    def __init__(self, response, operation_name):
        super().__init__(operation_name)
        self.response = response


# Never import an installed SDK or discover credentials. Every client is a fake;
# accidental unmocked construction fails instead of reaching AWS or IMDS.
sdk = ModuleType("boto3")
sdk.client = Mock(side_effect=AssertionError("Unmocked AWS client in unit test"))
sdk.Session = Mock(side_effect=AssertionError("Unmocked AWS session in unit test"))
botocore = ModuleType("botocore")
botocore.exceptions = ModuleType("botocore.exceptions")
botocore.exceptions.ClientError = ClientError
spec = importlib.util.spec_from_file_location("backup_recovery", Path(__file__).with_name("backup-recovery.py"))
module = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"boto3": sdk, "botocore": botocore,
                             "botocore.exceptions": botocore.exceptions}):
    spec.loader.exec_module(module)
NOW = datetime(2026, 9, 7, 15, tzinfo=timezone.utc)
RESOURCE = "arn:aws:ec2:us-west-1:111111111111:volume/vol-example"
POINT = {"ResourceArn": RESOURCE, "RecoveryPointArn": "arn:aws:ec2:us-west-1::snapshot/snap-example",
         "ResourceType": "EBS", "Status": "COMPLETED", "CreationDate": NOW,
         "IsEncrypted": True, "EncryptionKeyArn": "dr-key", "Lifecycle": {"DeleteAfterDays": 365}}
CONFIG = {"volumes": [RESOURCE], "primary_vault": "local", "dr_vault": "dr", "stage_vault": "stage",
          "dr_vault_arn": "dr-vault", "stage_vault_arn": "stage-vault", "dr_key": "dr-key", "copy_role": "copy-role",
          "restore_plan": "fleet", "restore_plan_arn": "plan-arn", "restore_role": "restore-role"}
SCHEDULED = datetime(2026, 9, 8, 12, tzinfo=timezone.utc)
PLAN = {"CreationTime": NOW, "RestoreTestingPlanArn": "plan-arn",
        "ScheduleExpression": "cron(0 12 8 * ? *)", "ScheduleExpressionTimezone": "Etc/UTC",
        "StartWindowHours": 1}
RESTORE_JOB = {"RestoreJobId": "restore-job", "IamRoleArn": "restore-role", "ResourceType": "EBS",
               "CreationDate": SCHEDULED + timedelta(minutes=15),
               "CompletionDate": SCHEDULED + timedelta(minutes=30),
               "CreatedBy": {"RestoreTestingPlanArn": "plan-arn"},
               "Status": "COMPLETED", "ValidationStatus": "SUCCESSFUL", "DeletionStatus": "SUCCESSFUL"}


class Backup:
    def __init__(self, points=None, jobs=None):
        self.points = points or []
        self.jobs = jobs or []
        self.started = []
        self.validation = []

    def get_paginator(self, operation):
        data = ({"RecoveryPoints": self.points} if operation == "list_recovery_points_by_backup_vault"
                else {"CopyJobs": self.jobs})
        return SimpleNamespace(paginate=lambda **kwargs: [data])

    def start_copy_job(self, **kwargs):
        self.started.append(kwargs)
        return {"CopyJobId": "job-" + str(len(self.started))}

    def describe_restore_job(self, **kwargs):
        return {"Status": "COMPLETED", "ResourceType": "EBS", "IamRoleArn": "restore-role",
                "CreatedResourceArn": "arn:aws:ec2:us-west-1:222222222222:volume/vol-test"}

    def put_restore_validation_result(self, **kwargs):
        self.validation.append(kwargs)


class RecoveryTests(unittest.TestCase):
    def test_missing_dr_seeds_only_allowed_recent_local_points(self):
        other = dict(POINT, ResourceArn="unrelated-volume")
        primary, dr, stage = Backup([POINT, other]), Backup(), Backup()
        missing, errors = module.reconcile(primary, dr, stage, CONFIG, NOW)
        self.assertEqual(errors, [])
        self.assertEqual(len(missing), 2)
        self.assertEqual(len(primary.started), 1)
        self.assertEqual(primary.started[0]["DestinationBackupVaultArn"], "dr-vault")
        self.assertEqual(dr.started, [])

    def test_stale_local_is_not_used_to_claim_recovery(self):
        primary = Backup([dict(POINT, CreationDate=NOW - timedelta(days=3))])
        missing, errors = module.reconcile(primary, Backup(), Backup(), CONFIG, NOW)
        self.assertIn("local backup older", missing[0])
        self.assertEqual(primary.started, [])

    def test_wrong_dr_key_never_crosses_accounts(self):
        dr = Backup([dict(POINT, EncryptionKeyArn="aws/ebs")])
        _, errors = module.reconcile(Backup([POINT]), dr, Backup(), CONFIG, NOW)
        self.assertIn("expected customer key", errors[0])
        self.assertEqual(dr.started, [])

    def test_copy_preserves_annual_retention_and_deduplicates(self):
        client, jobs = Backup(), []
        self.assertEqual(module.copy_point(client, POINT, "dr", "stage", jobs, "role", NOW), "started")
        self.assertEqual(client.started[0]["Lifecycle"], {"DeleteAfterDays": 365})
        self.assertEqual(module.copy_point(client, POINT, "dr", "stage", jobs, "role", NOW), "already-covered")
        self.assertEqual(len(client.started), 1)

    def test_copy_retries_are_bounded(self):
        failed = {"SourceRecoveryPointArn": POINT["RecoveryPointArn"], "DestinationBackupVaultArn": "stage",
                  "State": "FAILED", "CreationDate": NOW - timedelta(hours=7)}
        with self.assertRaisesRegex(RuntimeError, "three attempts"):
            module.copy_point(Backup(), POINT, "dr", "stage", [failed] * 3, "role", NOW)
        self.assertEqual(module.copy_point(Backup(), POINT, "dr", "stage",
                                          [dict(failed, CreationDate=NOW)], "role", NOW), "backoff")

    def test_restore_must_be_encrypted_detached_and_test_tagged(self):
        for encrypted, attachments, tags, expected in [
            (True, [], [{"Key": "awsbackup-restore-test", "Value": "test"}], "SUCCESSFUL"),
            (False, [], [{"Key": "awsbackup-restore-test", "Value": "test"}], "FAILED"),
            (True, [{"InstanceId": "unexpected-host"}], [{"Key": "awsbackup-restore-test", "Value": "test"}], "FAILED"),
            (True, [], [], "FAILED"),
        ]:
            backup = Backup()
            ec2 = SimpleNamespace(meta=SimpleNamespace(region_name="us-west-1"),
                                  describe_volumes=lambda **kwargs: {"Volumes": [{"State": "available",
                                      "Encrypted": encrypted, "Attachments": attachments, "Tags": tags}]})
            if expected == "FAILED":
                with self.assertRaises(RuntimeError):
                    module.validate_restore(backup, ec2, "job", "restore-role", "222222222222")
            else:
                module.validate_restore(backup, ec2, "job", "restore-role", "222222222222")
            self.assertEqual(backup.validation[0]["ValidationStatus"], expected)

    def test_cleanup_only_known_expired_detached_tests(self):
        deleted = []
        job = {"RestoreJobId": "job", "IamRoleArn": "restore-role", "ResourceType": "EBS",
               "CompletionDate": NOW - timedelta(hours=5),
               "CreatedResourceArn": "arn:aws:ec2:us-west-1:222222222222:volume/vol-test"}
        ec2 = SimpleNamespace(meta=SimpleNamespace(region_name="us-west-1"),
                              describe_volumes=lambda **kwargs: {"Volumes": [{"State": "available",
                                  "Attachments": [], "Tags": [{"Key": "awsbackup-restore-test"}]}]},
                              delete_volume=lambda **kwargs: deleted.append(kwargs))
        self.assertFalse(module.cleanup_expired_test(ec2, dict(job, IamRoleArn="other-role"),
                                                    "restore-role", "222222222222", NOW))
        self.assertFalse(module.cleanup_expired_test(ec2, dict(job, CompletionDate=NOW),
                                                    "restore-role", "222222222222", NOW))
        self.assertTrue(module.cleanup_expired_test(ec2, job, "restore-role", "222222222222", NOW))
        self.assertEqual(deleted, [{"VolumeId": "vol-test"}])


class MonthlyRestoreTests(unittest.TestCase):
    def stage(self, jobs_by_resource=None, plan=None):
        jobs_by_resource = jobs_by_resource or {}
        paginator = SimpleNamespace(paginate=Mock(side_effect=lambda **kwargs: [
            {"RestoreJobs": jobs_by_resource.get(kwargs["ResourceArn"], [])}]))
        return SimpleNamespace(
            get_restore_testing_plan=Mock(return_value={"RestoreTestingPlan": plan or PLAN}),
            get_paginator=Mock(return_value=paginator))

    def health(self, stage, now=None, config=None):
        return module.monthly_restore_health(stage, config or CONFIG, now or SCHEDULED + timedelta(hours=3))

    def test_cold_bootstrap_does_not_require_a_preexisting_monthly_test(self):
        stage = self.stage()
        self.assertEqual(self.health(stage, NOW), [])
        stage.get_paginator.assert_not_called()

    def test_missing_job_is_detected_without_any_event_after_start_window(self):
        stage = self.stage()
        self.assertEqual(self.health(stage, SCHEDULED + timedelta(hours=1, minutes=59)), [])
        self.assertIn("monthly restore test missing", self.health(stage, SCHEDULED + timedelta(hours=2))[0])
        stage.get_restore_testing_plan.assert_called_with(RestoreTestingPlanName="fleet")

    def test_monthly_boundaries_include_previous_month_and_previous_year(self):
        old_plan = dict(PLAN, CreationTime=datetime(2025, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(module.monthly_test_start(old_plan, NOW),
                         datetime(2026, 8, 8, 12, tzinfo=timezone.utc))
        self.assertEqual(module.monthly_test_start(old_plan, datetime(2026, 1, 1, tzinfo=timezone.utc)),
                         datetime(2025, 12, 8, 12, tzinfo=timezone.utc))

    def test_missing_or_changed_plan_does_not_receive_bootstrap_grace(self):
        stage = self.stage()
        stage.get_restore_testing_plan.side_effect = RuntimeError("ResourceNotFoundException")
        with self.assertRaisesRegex(RuntimeError, "ResourceNotFound"):
            self.health(stage)
        for change in [{"ScheduleExpression": "cron(0 12 9 * ? *)"},
                       {"ScheduleExpressionTimezone": "America/Los_Angeles"},
                       {"StartWindowHours": 24}, {"RestoreTestingPlanArn": "other-plan"}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.health(self.stage(plan=dict(PLAN, **change)))

    def test_every_configured_volume_needs_its_own_successful_test(self):
        stage = self.stage({RESOURCE: [RESTORE_JOB]})
        config = dict(CONFIG, volumes=[RESOURCE, "other-volume"])
        errors = self.health(stage, config=config)
        self.assertEqual(len(errors), 1)
        self.assertIn("other-volume", errors[0])
        self.assertEqual(stage.get_paginator.call_count, 2)

    def test_unrelated_role_plan_or_old_job_cannot_mask_missing_test(self):
        for changes in [{"IamRoleArn": "other-role"}, {"ResourceType": "EC2"},
                        {"CreatedBy": {"RestoreTestingPlanArn": "other-plan"}},
                        {"CreatedBy": {}}, {"CreationDate": SCHEDULED - timedelta(days=31)}]:
            with self.subTest(changes=changes):
                errors = self.health(self.stage({RESOURCE: [dict(RESTORE_JOB, **changes)]}))
                self.assertIn("monthly restore test missing", errors[0])

    def test_failed_aborted_and_validation_timeout_are_detected_without_events(self):
        for changes in [{"Status": "FAILED"}, {"Status": "ABORTED"},
                        {"ValidationStatus": "FAILED"}, {"ValidationStatus": "TIMED_OUT"},
                        {"DeletionStatus": "FAILED"}]:
            with self.subTest(changes=changes):
                errors = self.health(self.stage({RESOURCE: [dict(RESTORE_JOB, **changes)]}))
                self.assertEqual(len(errors), 1)

    def test_completed_but_unvalidated_job_is_not_success(self):
        stage = self.stage({RESOURCE: [dict(RESTORE_JOB, ValidationStatus="VALIDATING")]})
        self.assertEqual(self.health(stage, SCHEDULED + timedelta(hours=2)), [])
        self.assertIn("unvalidated after 2h", self.health(stage)[0])

    def test_running_job_has_bounded_completion_grace(self):
        stage = self.stage({RESOURCE: [dict(RESTORE_JOB, Status="RUNNING", ValidationStatus="")]})
        self.assertEqual(self.health(stage), [])
        self.assertIn("unfinished after 24h", self.health(stage, SCHEDULED + timedelta(days=1))[0])

    def test_new_success_clears_previous_attempt_failure_and_old_failure_does_not_linger(self):
        failed = dict(RESTORE_JOB, Status="FAILED", CreationDate=SCHEDULED)
        stage = self.stage({RESOURCE: [RESTORE_JOB, failed]})
        self.assertEqual(self.health(stage), [])
        next_month = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
        self.assertIn("monthly restore test missing", self.health(stage, next_month + timedelta(hours=3))[0])

    def test_terminal_validation_is_never_rewritten(self):
        backup, ec2 = Mock(), Mock()
        for status in ["SUCCESSFUL", "FAILED", "TIMED_OUT"]:
            backup.describe_restore_job.return_value = dict(RESTORE_JOB, ValidationStatus=status)
            module.validate_restore(backup, ec2, "job", "restore-role", "222222222222")
        backup.put_restore_validation_result.assert_not_called()
        ec2.describe_volumes.assert_not_called()

    def test_restore_event_status_and_backup_copy_state_alert(self):
        for detail_type, field in [("Restore Job State Change", "status"),
                                   ("Backup Job State Change", "state"),
                                   ("Copy Job State Change", "state")]:
            self.assertTrue(module.failed_job_event({"detail-type": detail_type, "detail": {field: "FAILED"}}))
            self.assertFalse(module.failed_job_event({"detail-type": detail_type, "detail": {field: "COMPLETED"}}))
        self.assertFalse(module.failed_job_event({}))


class HandlerTests(unittest.TestCase):
    def run_handler(self, restore_jobs, event=None, expected_error=None):
        stage = MonthlyRestoreTests().stage({RESOURCE: restore_jobs})
        resource_paginator = stage.get_paginator.return_value
        stage.get_paginator.side_effect = lambda operation: (
            resource_paginator if operation == "list_restore_jobs_by_protected_resource"
            else SimpleNamespace(paginate=Mock(return_value=[{"RestoreJobs": []}]))
        )
        clients = {service: Mock() for service in ["backup", "sts", "sns", "cloudwatch"]}
        clients["sts"].assume_role.return_value = {"Credentials": {
            "AccessKeyId": "mock", "SecretAccessKey": "mock", "SessionToken": "mock"}}
        stage_session = Mock()
        stage_session.client.side_effect = lambda service, **kwargs: stage if service == "backup" else Mock()
        config = dict(CONFIG, primary_region="us-west-1", observer_role="observer-role",
                      stage_account="222222222222", topic="topic")
        with patch.dict(module.os.environ, {"CONFIG": json.dumps(config)}), \
                patch.object(module.boto3, "client", side_effect=lambda service, **kwargs: clients[service]), \
                patch.object(module.boto3, "Session", return_value=stage_session), \
                patch.object(module, "reconcile", return_value=([], [])), \
                patch.object(module, "datetime", SimpleNamespace(now=lambda tz: SCHEDULED + timedelta(hours=3))):
            if expected_error:
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    module.handler(event or {}, None)
            else:
                self.assertEqual(module.handler(event or {}, None), {"missing": 0, "errors": 0})
        return clients

    def test_hourly_invocation_alarms_for_missing_test_without_restore_event(self):
        clients = self.run_handler([], expected_error="monthly restore test missing")
        metrics = clients["cloudwatch"].put_metric_data.call_args.kwargs["MetricData"]
        self.assertEqual({metric["MetricName"]: metric["Value"] for metric in metrics},
                         {"MissingRecoveryCopies": 0, "UnhealthyRestoreTests": 1, "RecoveryControllerErrors": 1})

    def test_hourly_invocation_alarms_for_failed_job_even_when_event_was_lost(self):
        self.run_handler([dict(RESTORE_JOB, Status="FAILED")], expected_error="monthly restore test FAILED")

    def test_healthy_test_reports_zero_and_failed_restore_event_still_notifies(self):
        clients = self.run_handler([RESTORE_JOB], event={
            "detail-type": "Restore Job State Change", "detail": {"status": "FAILED"}})
        clients["sns"].publish.assert_called_once()
        metrics = clients["cloudwatch"].put_metric_data.call_args.kwargs["MetricData"]
        self.assertTrue(all(metric["Value"] == 0 for metric in metrics))


if __name__ == "__main__":
    unittest.main()
