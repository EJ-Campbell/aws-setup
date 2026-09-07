"""Reconcile only the configured fleet's backup copies; never alter source volumes.

The hourly pass repairs lost EventBridge deliveries and seeds an empty encrypted DR
vault from recent local recovery points. Copies are idempotent; failed copies back off.
Restore validation checks detached encrypted EBS metadata, not guest contents/bootability.
Monthly per-volume checks do not rely on best-effort events or a successful scheduler.
"""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError


def pages(client, operation, result_key, **kwargs):
    return [item for page in client.get_paginator(operation).paginate(**kwargs)
            for item in page[result_key]]


def usable(points, allowed):
    return [point for point in points
            if point.get("ResourceType") == "EBS"
            and point.get("Status") == "COMPLETED"
            and point.get("ResourceArn") in allowed]


def latest(points, resource):
    return max((point for point in points if point["ResourceArn"] == resource),
               key=lambda point: point["CreationDate"], default=None)


def copy_point(client, point, source_vault, destination, jobs, role, now):
    """Only retry a terminal failure, after six hours, at most three times per point."""
    matching = [job for job in jobs
                if job.get("SourceRecoveryPointArn") == point["RecoveryPointArn"]
                and job.get("DestinationBackupVaultArn") == destination]
    if any(job["State"] in {"CREATED", "RUNNING", "COMPLETED"} for job in matching):
        return "already-covered"
    if len(matching) >= 3:
        raise RuntimeError("Copy exhausted three attempts for " + point["ResourceArn"])
    if matching and max(job["CreationDate"] for job in matching) > now - timedelta(hours=6):
        return "backoff"
    retention = int(point.get("Lifecycle", {}).get("DeleteAfterDays", 30))
    # Retain the original annual copies; weekly and initial seed copies keep 30 days.
    retention = 365 if retention >= 365 else 30
    token = hashlib.sha256((point["RecoveryPointArn"] + destination + str(len(matching))).encode()).hexdigest()[:50]
    result = client.start_copy_job(
        RecoveryPointArn=point["RecoveryPointArn"], SourceBackupVaultName=source_vault,
        DestinationBackupVaultArn=destination, IamRoleArn=role,
        IdempotencyToken=token, Lifecycle={"DeleteAfterDays": retention})
    jobs.append({"SourceRecoveryPointArn": point["RecoveryPointArn"],
                 "DestinationBackupVaultArn": destination, "State": "CREATED",
                 "CreationDate": now, "CopyJobId": result["CopyJobId"]})
    print(json.dumps({"action": "copy-started", "resource": point["ResourceArn"],
                      "copy_job_id": result["CopyJobId"], "retention_days": retention}))
    return "started"


def validate_restore(stage_backup, stage_ec2, job_id, restore_role, account):
    job = stage_backup.describe_restore_job(RestoreJobId=job_id)
    if (job.get("IamRoleArn") != restore_role or job.get("ResourceType") != "EBS"
            or job.get("Status") != "COMPLETED"
            or job.get("ValidationStatus") in {"SUCCESSFUL", "FAILED", "TIMED_OUT"}):
        return
    created = job.get("CreatedResourceArn", "")
    prefix = "arn:aws:ec2:" + stage_ec2.meta.region_name + ":" + account + ":volume/"
    if not created.startswith(prefix):
        raise ValueError("Unexpected resource ARN in restore test")
    volume_id = created[len(prefix):]
    volumes = stage_ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
    passed = (len(volumes) == 1 and volumes[0].get("Encrypted") is True
              and volumes[0].get("State") == "available"
              and not volumes[0].get("Attachments")
              and any(tag["Key"] == "awsbackup-restore-test" for tag in volumes[0].get("Tags", [])))
    stage_backup.put_restore_validation_result(
        RestoreJobId=job_id, ValidationStatus="SUCCESSFUL" if passed else "FAILED",
        ValidationStatusMessage=("Detached encrypted test volume restored; guest boot/data not tested."
                                 if passed else "Restored volume failed encryption, isolation, or test-tag checks."))
    if not passed:
        raise RuntimeError("Restore validation failed for " + job_id)


def cleanup_expired_test(stage_ec2, job, restore_role, account, now):
    """Backstop AWS Backup cleanup only for this role's old, detached test volumes."""
    if (job.get("IamRoleArn") != restore_role or job.get("ResourceType") != "EBS"
            or job.get("DeletionStatus") == "SUCCESSFUL"
            or job.get("CompletionDate", now) > now - timedelta(hours=4)):
        return False
    prefix = "arn:aws:ec2:" + stage_ec2.meta.region_name + ":" + account + ":volume/"
    created = job.get("CreatedResourceArn", "")
    if not created.startswith(prefix):
        return False
    volume_id = created[len(prefix):]
    try:
        volume = stage_ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    except ClientError as error:
        if error.response["Error"]["Code"] == "InvalidVolume.NotFound":
            return False
        raise
    if (volume.get("State") != "available" or volume.get("Attachments")
            or not any(tag["Key"] == "awsbackup-restore-test" for tag in volume.get("Tags", []))):
        raise RuntimeError("Expired restore-test volume is not safe to clean up: " + volume_id)
    stage_ec2.delete_volume(VolumeId=volume_id)
    print(json.dumps({"action": "expired-test-volume-removed", "volume": volume_id, "restore_job": job["RestoreJobId"]}))
    return True


def monthly_test_start(plan, now):
    """Match the opinionated Terraform schedule; never silently accept schedule drift."""
    if (plan.get("ScheduleExpression") != "cron(0 12 8 * ? *)"
            or plan.get("ScheduleExpressionTimezone", "Etc/UTC") not in {"Etc/UTC", "UTC"}
            or plan.get("StartWindowHours") != 1):
        raise ValueError("Unexpected monthly restore-test schedule")
    scheduled = now.astimezone(timezone.utc).replace(day=8, hour=12, minute=0, second=0, microsecond=0)
    if scheduled > now:
        scheduled = (scheduled.replace(day=1) - timedelta(days=1)).replace(day=8)
    # A newly created plan did not owe a test before it existed. A deleted plan or
    # denied metadata request must raise instead of being interpreted as this grace.
    return scheduled if plan["CreationTime"] <= scheduled else None


def monthly_restore_health(stage, config, now):
    """Require the latest scheduled test for every allowed source, even with no events.

    Use the per-resource API, not optional newer SourceResourceArn response fields:
    older Lambda SDK models drop those fields, and recovery points may have expired.
    An unrelated plan/role or a successful test of another volume cannot satisfy this.
    """
    plan = stage.get_restore_testing_plan(
        RestoreTestingPlanName=config["restore_plan"])["RestoreTestingPlan"]
    if plan["RestoreTestingPlanArn"] != config["restore_plan_arn"]:
        raise ValueError("Unexpected restore-testing plan ARN")
    scheduled = monthly_test_start(plan, now)
    if scheduled is None:
        return []
    errors = []
    for resource in sorted(set(config["volumes"])):
        jobs = pages(stage, "list_restore_jobs_by_protected_resource", "RestoreJobs",
                     ResourceArn=resource,
                     ByRecoveryPointCreationDateAfter=scheduled - timedelta(days=36))
        matching = [job for job in jobs
                    if job.get("IamRoleArn") == config["restore_role"]
                    and job.get("ResourceType") == "EBS"
                    and job.get("CreatedBy", {}).get("RestoreTestingPlanArn") == config["restore_plan_arn"]
                    and job["CreationDate"] >= scheduled]
        job = max(matching, key=lambda item: item["CreationDate"], default=None)
        if job is None:
            # AWS may start anywhere in the one-hour window. Allow another hour
            # for metadata propagation, but never wait a month to detect no job.
            if now >= scheduled + timedelta(hours=2):
                errors.append("monthly restore test missing since " + scheduled.isoformat() + ": " + resource)
            continue
        job_id = job["RestoreJobId"]
        if job.get("Status") in {"FAILED", "ABORTED"}:
            errors.append("monthly restore test " + job["Status"] + ": " + resource + " (" + job_id + ")")
        elif job.get("ValidationStatus") in {"FAILED", "TIMED_OUT"}:
            errors.append("monthly restore validation " + job["ValidationStatus"] + ": " + resource + " (" + job_id + ")")
        elif job.get("Status") == "COMPLETED":
            if (job.get("ValidationStatus") != "SUCCESSFUL"
                    and now >= job.get("CompletionDate", job["CreationDate"]) + timedelta(hours=2)):
                errors.append("monthly restore test unvalidated after 2h: " + resource + " (" + job_id + ")")
        elif now >= scheduled + timedelta(hours=24):
            errors.append("monthly restore test unfinished after 24h: " + resource + " (" + job_id + ")")
        if job.get("DeletionStatus") == "FAILED":
            errors.append("AWS Backup restore-test cleanup failed: " + job_id)
    return errors


def failed_job_event(event):
    detail = event.get("detail", {})
    field = "status" if event.get("detail-type") == "Restore Job State Change" else "state"
    return detail.get(field) in {"FAILED", "EXPIRED", "ABORTED", "PARTIAL"}


def reconcile(primary, dr, stage, config, now):
    allowed = set(config["volumes"])
    primary_points = usable(pages(primary, "list_recovery_points_by_backup_vault", "RecoveryPoints",
                                   BackupVaultName=config["primary_vault"]), allowed)
    dr_points = usable(pages(dr, "list_recovery_points_by_backup_vault", "RecoveryPoints",
                            BackupVaultName=config["dr_vault"]), allowed)
    stage_points = usable(pages(stage, "list_recovery_points_by_backup_vault", "RecoveryPoints",
                               BackupVaultName=config["stage_vault"]), allowed)
    since = now - timedelta(days=14)
    primary_jobs = pages(primary, "list_copy_jobs", "CopyJobs", ByCreatedAfter=since)
    dr_jobs = pages(dr, "list_copy_jobs", "CopyJobs", ByCreatedAfter=since)
    missing = []
    errors = []
    for resource in sorted(allowed):
        source = latest(primary_points, resource)
        intermediate = latest(dr_points, resource)
        destination = latest(stage_points, resource)
        if source is None or source["CreationDate"] < now - timedelta(hours=48):
            missing.append("local backup older than 48h: " + resource)
            continue
        if intermediate is None or intermediate["CreationDate"] < now - timedelta(days=8):
            missing.append("encrypted DR copy missing/older than 8d: " + resource)
            try:
                copy_point(primary, source, config["primary_vault"], config["dr_vault_arn"],
                           primary_jobs, config["copy_role"], now)
            except Exception as error:
                errors.append(str(error))
        if destination is None or destination["CreationDate"] < now - timedelta(days=8):
            missing.append("cross-account copy missing/older than 8d: " + resource)
    # Eight days includes every new weekly/monthly point but stays inside the 14-day
    # copy-job deduplication window, avoiding repeats after AWS expires job history.
    for point in dr_points:
        if point["CreationDate"] < now - timedelta(days=8):
            continue
        if not point.get("IsEncrypted") or point.get("EncryptionKeyArn") != config["dr_key"]:
            errors.append("DR recovery point is not encrypted with the expected customer key: " + point["RecoveryPointArn"])
            continue
        try:
            copy_point(dr, point, config["dr_vault"], config["stage_vault_arn"],
                       dr_jobs, config["copy_role"], now)
        except Exception as error:
            errors.append(str(error))
    return missing, errors


def handler(event, context):
    config = json.loads(os.environ["CONFIG"])
    now = datetime.now(timezone.utc)
    primary = boto3.client("backup", region_name=config["primary_region"])
    dr = boto3.client("backup", region_name="us-east-1")
    credentials = boto3.client("sts").assume_role(
        RoleArn=config["observer_role"], RoleSessionName="backup-recovery")['Credentials']
    stage_session = boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
                                 aws_secret_access_key=credentials['SecretAccessKey'],
                                 aws_session_token=credentials['SessionToken'])
    stage = stage_session.client("backup", region_name=config["primary_region"])
    stage_ec2 = stage_session.client("ec2", region_name=config["primary_region"])
    sns = boto3.client("sns", region_name=config["primary_region"])
    if failed_job_event(event):
        sns.publish(TopicArn=config["topic"], Subject="AWS Backup job requires attention",
                    Message=json.dumps(event, default=str))
    try:
        missing, errors = reconcile(primary, dr, stage, config, now)
        # The periodic pass also handles a missed restore-completed event.
        for job in pages(stage, "list_restore_jobs", "RestoreJobs",
                         ByCreatedAfter=now - timedelta(days=40),
                         ByRestoreTestingPlanArn=config["restore_plan_arn"]):
            if job.get("IamRoleArn") == config["restore_role"]:
                recent = job.get("CompletionDate", now) > now - timedelta(hours=4)
                try:
                    if recent and job.get("DeletionStatus") != "SUCCESSFUL":
                        validate_restore(stage, stage_ec2, job["RestoreJobId"], config["restore_role"], config["stage_account"])
                    if recent and job.get("DeletionStatus") == "FAILED":
                        errors.append("AWS Backup restore-test cleanup failed: " + job["RestoreJobId"])
                except Exception as error:
                    errors.append(str(error))
                try:
                    cleanup_expired_test(stage_ec2, job, config["restore_role"], config["stage_account"], now)
                except Exception as error:
                    errors.append(str(error))
        # Query current metadata after validation so a just-validated job can count
        # as healthy. Missing/failed monthly tests remain visible if events vanish.
        restore_errors = monthly_restore_health(stage, config, now)
        errors.extend(restore_errors)
        boto3.client("cloudwatch", region_name=config["primary_region"]).put_metric_data(
            Namespace="FleetBackup", MetricData=[
                {"MetricName": "MissingRecoveryCopies", "Value": len(missing), "Unit": "Count"},
                {"MetricName": "UnhealthyRestoreTests", "Value": len(restore_errors), "Unit": "Count"},
                {"MetricName": "RecoveryControllerErrors", "Value": len(errors), "Unit": "Count"}])
        print(json.dumps({"missing": missing, "errors": errors}))
        if errors:
            raise RuntimeError("; ".join(errors))
    except Exception:
        # Lambda Errors alarm covers API errors as well as application failures.
        print("Backup recovery reconciliation failed; see the exception and alarm.")
        raise
    return {"missing": len(missing), "errors": len(errors)}
