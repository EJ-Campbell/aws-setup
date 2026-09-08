"""Offline tests for the exact Terraform-packaged security delivery observer.

No AWS calls: fake clients expose only the observer's narrow read/metric methods.
Run on a development server: python3 -S -B scripts/test-security-delivery.py
The loader injects SDK stubs, so site-packages and AWS credentials are unnecessary.
"""
import concurrent.futures
import contextlib
import copy
import datetime
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import threading
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TERRAFORM = (ROOT / "security-monitoring.tf").read_text()
REGIONAL = (ROOT / "modules/security-region/main.tf").read_text()
SOURCE = textwrap.dedent(re.search(
    r"security_delivery_watchdog = <<-PYTHON\n(.*?)^  PYTHON$", TERRAFORM, re.M | re.S
).group(1))
REGIONS = re.findall(r'"([a-z]{2}-[a-z]+-\d)"', re.search(
    r"security_delivery_regions = \[(.*?)\n  \]", TERRAFORM, re.S
).group(1))
MAIN, STAGING = "111111111111", "222222222222"
SNS_TOPIC = "arn:aws:sns:us-west-1:" + MAIN + ":cost-alerts"
NOW = datetime.datetime(2026, 9, 7, 12, tzinfo=datetime.timezone.utc)
COUNTERS = ["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible", "ApproximateNumberOfMessagesDelayed"]


class Config:
    def __init__(self, **kwargs):
        self.values = kwargs


class CloudWatch:
    def __init__(self, factory, account, region):
        self.factory, self.account, self.region = factory, account, region

    def get_metric_data(self, **kwargs):
        self.factory.reads.append((self.account, self.region, kwargs))
        response = {"MetricDataResults": [
            {"Id": query["Id"], "StatusCode": "Complete", "Values": [], "Timestamps": []}
            for query in kwargs["MetricDataQueries"]
        ]}
        hook = self.factory.metrics.get((self.account, self.region))
        return hook(response) if hook else response

    def put_metric_data(self, **kwargs):
        if self.factory.publish_error:
            raise RuntimeError("synthetic private diagnostic never logged")
        self.factory.published.append(kwargs)
        return {}


class SQS:
    def __init__(self, factory, account, region):
        self.factory, self.account, self.region = factory, account, region

    def get_queue_attributes(self, **kwargs):
        self.factory.queue_reads.append((self.account, self.region, kwargs))
        queue = kwargs["QueueUrl"].rsplit("/", 1)[1]
        result = self.factory.queues.get((self.account, self.region, queue), {key: "0" for key in COUNTERS})
        if isinstance(result, Exception):
            raise result
        return {"Attributes": copy.deepcopy(result)}


class Events:
    def __init__(self, factory, account, region):
        self.factory, self.account, self.region = factory, account, region

    def describe_rule(self, **kwargs):
        self.factory.rule_reads.append((self.account, self.region, kwargs))
        name, bus = kwargs["Name"], kwargs.get("EventBusName")
        response = {"Name": name, "State": "ENABLED",
                    "Arn": "arn:aws:events:" + self.region + ":" + self.account + ":rule/" + (bus + "/" if bus else "") + name}
        if name == "security-delivery-health":
            response["ScheduleExpression"] = "rate(5 minutes)"
        override = self.factory.rules.get((self.account, self.region, name))
        if isinstance(override, Exception):
            raise override
        return override(copy.deepcopy(response)) if override else response

    def list_targets_by_rule(self, **kwargs):
        self.factory.target_reads.append((self.account, self.region, kwargs))
        assert kwargs["Limit"] == 2 and "NextToken" not in kwargs
        rule = kwargs["Rule"]
        if rule == "security-forward-findings":
            target = {"Id": "central-security-alerts", "Arn": "arn:aws:events:us-west-1:" + MAIN + ":event-bus/security-alerts",
                      "RoleArn": "arn:aws:iam::" + self.account + ":role/security-findings-forward",
                      "DeadLetterConfig": {"Arn": "arn:aws:sqs:" + self.region + ":" + self.account + ":security-findings-delivery-dlq"},
                      "RetryPolicy": {"MaximumEventAgeInSeconds": 86400, "MaximumRetryAttempts": 185}}
        elif rule == "security-alerts-notify":
            target = {"Id": "confirmed-operator-email", "Arn": SNS_TOPIC,
                      "RoleArn": "arn:aws:iam::" + MAIN + ":role/security-alerts-notify",
                      "DeadLetterConfig": {"Arn": "arn:aws:sqs:us-west-1:" + MAIN + ":security-central-delivery-dlq"},
                      "RetryPolicy": {"MaximumEventAgeInSeconds": 86400, "MaximumRetryAttempts": 185}}
        elif rule == "security-delivery-health":
            target = {"Id": rule, "Arn": "arn:aws:lambda:us-west-1:" + MAIN + ":function:security-delivery-health",
                      "DeadLetterConfig": {"Arn": "arn:aws:sqs:us-west-1:" + MAIN + ":security-central-delivery-dlq"},
                      "RetryPolicy": {"MaximumEventAgeInSeconds": 300, "MaximumRetryAttempts": 2}}
        else:
            raise AssertionError("Unexpected rule " + rule)
        response = {"Targets": [target]}
        override = self.factory.targets.get((self.account, self.region, rule))
        if isinstance(override, Exception):
            raise override
        return override(copy.deepcopy(response)) if override else response


class STS:
    def __init__(self, factory):
        self.factory = factory

    def assume_role(self, **kwargs):
        self.factory.assumed.append(kwargs)
        if self.factory.assume_error:
            raise RuntimeError("synthetic secret must not appear in logs")
        return {"Credentials": {"AccessKeyId": "synthetic-access", "SecretAccessKey": "synthetic-secret", "SessionToken": "synthetic-session"}}


class Session:
    def __init__(self, factory, account):
        self.factory, self.account = factory, account

    def client(self, name, region_name="us-west-1", config=None):
        # Boto3 Sessions must never be used concurrently from worker threads.
        assert threading.get_ident() == self.factory.main_thread
        assert config.values == {"connect_timeout": 2, "read_timeout": 3, "retries": {"total_max_attempts": 1}}
        if (self.account, region_name) in self.factory.client_errors:
            raise RuntimeError("synthetic client failure")
        if name == "cloudwatch":
            return CloudWatch(self.factory, self.account, region_name)
        if name == "sqs":
            return SQS(self.factory, self.account, region_name)
        if name == "events":
            return Events(self.factory, self.account, region_name)
        if name == "sts" and self.account == MAIN:
            return STS(self.factory)
        raise AssertionError("Unexpected AWS capability: " + name)


class Factory:
    def __init__(self):
        self.main_thread = threading.get_ident()
        self.reads, self.queue_reads, self.published, self.assumed = [], [], [], []
        self.metrics, self.queues, self.client_errors = {}, {}, set()
        self.rules, self.targets = {}, {}
        self.rule_reads, self.target_reads = [], []
        self.assume_error = self.publish_error = False

    def Session(self, **kwargs):
        if "aws_access_key_id" in kwargs:
            assert kwargs == {"aws_access_key_id": "synthetic-access", "aws_secret_access_key": "synthetic-secret", "aws_session_token": "synthetic-session"}
            return Session(self, STAGING)
        assert kwargs == {"region_name": "us-west-1"}
        return Session(self, MAIN)


def load(factory):
    config_module = types.ModuleType("botocore.config")
    config_module.Config = Config
    fake_modules = {"boto3": types.SimpleNamespace(Session=factory.Session),
                    "botocore": types.ModuleType("botocore"), "botocore.config": config_module}
    namespace = {}
    with patch.dict(sys.modules, fake_modules):
        exec(compile(SOURCE, "security-monitoring.tf:watchdog", "exec"), namespace)
    return namespace


def block(source, resource_type, name):
    start = source.index('resource "' + resource_type + '" "' + name + '" {')
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[start:index + 1]
    raise AssertionError("Unclosed Terraform resource")


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.factory = Factory()
        self.module = load(self.factory)

    def run_handler(self, regions=None, extra=None):
        env = {"MAIN_ACCOUNT": MAIN, "STAGING_ACCOUNT": STAGING, "REGIONS": json.dumps(regions or REGIONS), "SNS_TOPIC_ARN": SNS_TOPIC}
        env.update(extra or {})
        output = io.StringIO()
        with patch.dict(os.environ, env), contextlib.redirect_stdout(output):
            values = self.module["handler"]({}, None)
        return values, json.loads(output.getvalue())

    def inspect(self, account=MAIN, region="us-east-1"):
        return self.module["inspect_region"](CloudWatch(self.factory, account, region),
            SQS(self.factory, account, region), Events(self.factory, account, region), account, region, MAIN, SNS_TOPIC, NOW)

    def test_complete_empty_failure_metrics_are_healthy(self):
        values, log = self.run_handler()
        self.assertEqual(values, {"FailedDeliveries": 0, "QueuedEvents": 0, "ObserverErrors": 0, "Heartbeat": 1})
        self.assertEqual(log, {"checked_regions": 34, "unhealthy": []})

    def test_exact_coverage_and_monthly_metric_request_budget(self):
        self.run_handler()
        self.assertEqual(len(REGIONS), 17)
        self.assertEqual({(account, region) for account, region, _ in self.factory.reads},
                         {(account, region) for account in (MAIN, STAGING) for region in REGIONS})
        requested = sum(len(call["MetricDataQueries"]) for _, _, call in self.factory.reads)
        self.assertEqual(requested, 72)
        self.assertEqual(requested * 288 * 30, 622080)
        self.assertEqual(len(self.factory.queue_reads), 35)
        self.assertEqual(len(self.factory.rule_reads), 36)
        self.assertEqual(len(self.factory.target_reads), 36)

    def test_disabled_missing_or_wrong_rule_is_not_a_healthy_quiet_region(self):
        for override in (lambda r: dict(r, State="DISABLED"), lambda r: {},
                         lambda r: dict(r, Name="other"), lambda r: dict(r, Arn="other"),
                         RuntimeError("ResourceNotFoundException"), TimeoutError("private diagnostic")):
            with self.subTest(override=override):
                self.factory.rules[(MAIN, "us-east-1", "security-forward-findings")] = override
                values, log = self.run_handler(["us-east-1"])
                self.assertGreaterEqual(values["ObserverErrors"], 1)
                self.assertEqual(values["FailedDeliveries"], 0)
                self.assertEqual(values["QueuedEvents"], 0)
                self.assertNotIn("private diagnostic", json.dumps(log))

    def test_removed_duplicate_paginated_or_denied_targets_fail_closed(self):
        for override in (lambda r: {"Targets": []}, lambda r: {},
                         lambda r: {"Targets": r["Targets"] * 2}, lambda r: dict(r, NextToken="do-not-follow"),
                         RuntimeError("AccessDenied"), TimeoutError("private diagnostic")):
            with self.subTest(override=override):
                self.factory.targets[(STAGING, "us-east-1", "security-forward-findings")] = override
                values, _ = self.run_handler(["us-east-1"])
                self.assertGreaterEqual(values["ObserverErrors"], 1)

    def test_target_destination_role_dlq_retries_and_payload_are_exact(self):
        for rule in ("security-forward-findings", "security-alerts-notify", "security-delivery-health"):
            for key, value in (("Arn", "arn:foreign"), ("RoleArn", "arn:foreign"), ("Id", "other"),
                               ("DeadLetterConfig", {}), ("RetryPolicy", {}), ("Input", "{}"),
                               ("InputTransformer", {})):
                def change(response):
                    response["Targets"][0][key] = value
                    return response
                with self.subTest(rule=rule, key=key):
                    self.factory.targets = {(MAIN, "us-west-1", rule): change}
                    self.assertGreaterEqual(self.inspect(region="us-west-1")["errors"], 1)

    def test_central_rules_and_watchdog_schedule_are_independently_checked(self):
        for rule in ("security-alerts-notify", "security-delivery-health"):
            with self.subTest(rule=rule):
                self.factory.rules = {(MAIN, "us-west-1", rule): lambda r: dict(r, State="DISABLED")}
                self.assertGreaterEqual(self.inspect(region="us-west-1")["errors"], 1)
        self.factory.rules = {(MAIN, "us-west-1", "security-delivery-health"): lambda r: dict(r, ScheduleExpression="rate(1 day)")}
        self.assertGreaterEqual(self.inspect(region="us-west-1")["errors"], 1)
        central = [request for _, _, request in self.factory.rule_reads if request["Name"] == "security-alerts-notify"]
        self.assertTrue(all(request["EventBusName"] == "security-alerts" for request in central))

    def test_event_api_failure_does_not_skip_other_read_only_health_checks(self):
        self.factory.rules[(MAIN, "us-east-1", "security-forward-findings")] = TimeoutError("unavailable")
        result = self.inspect()
        self.assertEqual(result["errors"], 1)
        self.assertEqual(len(self.factory.target_reads), 1)
        self.assertEqual(len(self.factory.reads), 1)
        self.assertEqual(len(self.factory.queue_reads), 1)

    def test_metric_names_case_dimensions_and_query_window(self):
        self.inspect(region="us-west-1")
        request = self.factory.reads[0][2]
        queries = request["MetricDataQueries"]
        self.assertEqual(request["StartTime"], NOW - datetime.timedelta(minutes=15))
        self.assertEqual(request["EndTime"], NOW)
        self.assertEqual(request["MaxDatapoints"], 100)
        self.assertEqual(len(queries), 6)
        for index, query in enumerate(queries):
            metric = query["MetricStat"]["Metric"]
            self.assertEqual(metric["MetricName"], ["FailedInvocations", "InvocationsFailedToBeSentToDlq"][index % 2])
            self.assertEqual(query["MetricStat"]["Stat"], "Sum")
            self.assertEqual(query["MetricStat"]["Period"], 300)
            dimensions = {item["Name"]: item["Value"] for item in metric["Dimensions"]}
            self.assertEqual(dimensions.get("EventBusName"), "security-alerts" if index in (2, 3) else None)

    def test_staging_west1_does_not_query_main_only_resources(self):
        self.inspect(account=STAGING, region="us-west-1")
        self.assertEqual(len(self.factory.reads[0][2]["MetricDataQueries"]), 2)
        self.assertEqual(len(self.factory.queue_reads), 1)

    def test_failure_and_all_queue_states_raise_health_gauges(self):
        def failures(response):
            response["MetricDataResults"][0]["Values"] = [1, 2]
            response["MetricDataResults"][1]["Values"] = [1]
            return response
        self.factory.metrics[(MAIN, "us-east-1")] = failures
        self.factory.queues[(STAGING, "us-east-1", "security-findings-delivery-dlq")] = dict(zip(COUNTERS, ["2", "3", "4"]))
        values, log = self.run_handler(["us-east-1"])
        self.assertEqual(values["FailedDeliveries"], 4)
        self.assertEqual(values["QueuedEvents"], 9)
        self.assertEqual(values["ObserverErrors"], 0)
        self.assertEqual(len(log["unhealthy"]), 2)

    def test_partial_paginated_missing_duplicate_unknown_and_messages_are_errors(self):
        def partial(response):
            response["MetricDataResults"][0]["StatusCode"] = "PartialData"
            return response
        def missing(response):
            response["MetricDataResults"].pop()
            return response
        def duplicate(response):
            response["MetricDataResults"][1]["Id"] = "m0"
            return response
        def unknown(response):
            response["MetricDataResults"][1]["Id"] = "foreign"
            return response
        for change in (partial, missing, duplicate, unknown,
                       lambda response: dict(response, NextToken="bounded-do-not-follow"),
                       lambda response: dict(response, Messages=[{"Code": "InternalError"}])):
            with self.subTest(change=change):
                self.factory.metrics[(MAIN, "us-east-1")] = change
                self.assertGreaterEqual(self.inspect()["errors"], 1)

    def test_invalid_metric_values_never_publish_nan_or_negative_success(self):
        for invalid in ([-1], [float("nan")], [float("inf")], ["1"], [True], {}):
            def malformed(response):
                response["MetricDataResults"][0]["Values"] = invalid
                return response
            with self.subTest(invalid=invalid):
                self.factory.metrics[(MAIN, "us-east-1")] = malformed
                result = self.inspect()
                self.assertGreaterEqual(result["errors"], 1)
                self.assertEqual(result["failures"], 0)

    def test_queue_missing_malformed_or_denied_is_not_healthy_zero(self):
        for invalid in ({}, {key: "bad" for key in COUNTERS}, {key: "-1" for key in COUNTERS}, RuntimeError("denied")):
            with self.subTest(invalid=invalid):
                self.factory.queues[(MAIN, "us-east-1", "security-findings-delivery-dlq")] = invalid
                self.assertGreaterEqual(self.inspect()["errors"], 1)

    def test_cloudwatch_timeout_does_not_skip_dlq_count(self):
        def timeout(response):
            raise TimeoutError("synthetic secret-bearing diagnostic")
        self.factory.metrics[(MAIN, "us-east-1")] = timeout
        result = self.inspect()
        self.assertEqual(result["errors"], 1)
        self.assertEqual(len(self.factory.queue_reads), 1)

    def test_assume_failure_checks_main_and_reports_partial_coverage(self):
        self.factory.assume_error = True
        values, log = self.run_handler()
        self.assertEqual(log["checked_regions"], 17)
        self.assertEqual(values["ObserverErrors"], 1)
        self.assertEqual(values["Heartbeat"], 1)
        self.assertNotIn("synthetic", json.dumps(log))

    def test_exact_read_role_short_session_and_no_credential_log(self):
        _, log = self.run_handler(["us-east-1"])
        self.assertEqual(self.factory.assumed, [{"RoleArn": "arn:aws:iam::" + STAGING + ":role/security-delivery-observer",
                         "RoleSessionName": "security-delivery-health", "DurationSeconds": 900}])
        self.assertNotIn("synthetic", json.dumps(log))

    def test_client_and_worker_exceptions_are_observer_errors(self):
        self.factory.client_errors.add((STAGING, "us-east-1"))
        values, log = self.run_handler(["us-east-1"])
        self.assertEqual(values["ObserverErrors"], 1)
        self.assertEqual(log["checked_regions"], 1)
        with patch.dict(self.module, inspect_region=lambda *args: (_ for _ in ()).throw(RuntimeError("failure"))):
            values, log = self.run_handler(["us-east-1"])
        self.assertEqual(values["ObserverErrors"], 2)
        self.assertEqual(log["checked_regions"], 0)

    def test_only_scoped_counts_are_read_and_four_metrics_are_published(self):
        self.run_handler(["us-west-1"])
        for account, region, request in self.factory.queue_reads:
            self.assertTrue(request["QueueUrl"].startswith("https://sqs." + region + ".amazonaws.com/" + account + "/security-"))
            self.assertEqual(request["AttributeNames"], COUNTERS)
        self.assertEqual(len(self.factory.published), 1)
        publish = self.factory.published[0]
        self.assertEqual(publish["Namespace"], "SecurityDelivery")
        self.assertEqual(len(publish["MetricData"]), 4)
        self.assertTrue(all(metric["Unit"] == "Count" for metric in publish["MetricData"]))

    def test_failed_publish_never_reports_a_successful_heartbeat(self):
        self.factory.publish_error = True
        with self.assertRaises(RuntimeError):
            self.run_handler(["us-east-1"])
        self.assertEqual(self.factory.published, [])

    def test_bounded_region_account_validation_happens_before_aws_calls(self):
        for invalid in ([], ["us-east-1"] * 18, ["us-east-1", "us-east-1"], [None], [{}], ["../host"], "us-east-1"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.run_handler(extra={"REGIONS": json.dumps(invalid)})
        for invalid in ({"MAIN_ACCOUNT": "invalid"}, {"STAGING_ACCOUNT": MAIN},
                        {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:" + MAIN + ":wrong-region"},
                        {"SNS_TOPIC_ARN": "arn:aws:sns:us-west-1:" + STAGING + ":wrong-account"}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.run_handler(extra=invalid)
        self.assertEqual(self.factory.assumed, [])
        self.assertEqual(self.factory.reads, [])

    def test_worker_concurrency_is_capped_at_six(self):
        original = concurrent.futures.ThreadPoolExecutor
        with patch.object(concurrent.futures, "ThreadPoolExecutor", wraps=original) as executor:
            self.run_handler()
        executor.assert_called_once_with(max_workers=6)


class TerraformSafetyTests(unittest.TestCase):
    def test_posture_covers_both_source_regions_and_final_recovery_region(self):
        expected = {"security_main_us_west_1", "security_main_us_west_2",
                    "security_main_us_east_1", "security_staging_us_west_1",
                    "security_staging_us_east_1"}
        enabled = set()
        for name, body in re.findall(r'^module "([^"]+)" \{(.*?)^\}', TERRAFORM, re.M | re.S):
            if re.search(r'\bposture_enabled\s*=\s*local\.security_posture_enabled\b', body):
                enabled.add(name)
        self.assertEqual(enabled, expected)

    def test_posture_staged_off_without_disabling_foundation(self):
        self.assertRegex(TERRAFORM, r'\bsecurity_posture_enabled\s*=\s*false\b')
        self.assertNotRegex(TERRAFORM, r'\bposture_enabled\s*=\s*true\b')
        for kind, name in (("aws_cloudcontrolapi_resource", "guardduty"),
                           ("aws_accessanalyzer_analyzer", "external")):
            self.assertNotIn("posture_enabled", block(REGIONAL, kind, name))

    def test_defaults_have_a_single_separate_owner(self):
        defaults = (ROOT / "modules/security-defaults/main.tf").read_text()
        for kind in ("aws_ebs_encryption_by_default", "aws_ebs_snapshot_block_public_access",
                     "aws_ec2_instance_metadata_defaults"):
            self.assertNotIn(kind, REGIONAL)
            self.assertNotIn("posture_enabled", block(defaults, kind, "security"))

    def test_monitoring_reuses_shared_provider_aliases(self):
        self.assertNotRegex(TERRAFORM, re.compile(r'^provider "aws"', re.M))
        east1 = re.search(r'^module "security_staging_us_east_1" \{(.*?)^\}', TERRAFORM, re.M | re.S).group(1)
        self.assertRegex(east1, r'providers\s*=\s*\{ aws = aws\.staging_dr \}')
        self.assertNotIn("aws.security_staging_us_east_1", TERRAFORM)

    def test_guardduty_all_current_optional_features_are_disabled_at_creation(self):
        features = re.search(r'guardduty_optional_features\s*=\s*\[([^]]+)\]', REGIONAL)
        self.assertIsNotNone(features)
        self.assertEqual(set(re.findall(r'"([A-Z0-9_]+)"', features.group(1))),
                         {"S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION",
                          "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "RUNTIME_MONITORING",
                          "AI_PROTECTION", "AI_ANALYST"})
        detector = block(REGIONAL, "aws_cloudcontrolapi_resource", "guardduty")
        self.assertIn('type_name = "AWS::GuardDuty::Detector"', detector)
        self.assertRegex(detector, r'Enable\s*=\s*true')
        self.assertIn('Name = name, Status = "DISABLED"', detector)
        self.assertIn('Name = agent, Status = "DISABLED"', detector)
        self.assertNotRegex(REGIONAL, re.compile(r'^resource "aws_guardduty_detector(?:_feature)?"', re.M))
        self.assertNotIn("DataSources", detector)
        self.assertIn('prevent_destroy = true', detector)
        self.assertIn('jsondecode(self.properties).Enable == true', detector)
        self.assertIn('name, "MISSING") == "DISABLED"', detector)
        self.assertIn('feature.Status == "DISABLED"', detector)

    def test_guardduty_nested_agent_postcondition_is_strict(self):
        detector = block(REGIONAL, "aws_cloudcontrolapi_resource", "guardduty")
        agents = re.search(r'guardduty_runtime_agents\s*=\s*(\[[^]]+\])', REGIONAL)
        self.assertIsNotNone(agents)
        self.assertEqual(set(json.loads(agents.group(1))),
                         {"EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT", "EC2_AGENT_MANAGEMENT"})
        self.assertIn('AdditionalConfiguration = [for agent in local.guardduty_runtime_agents', detector)
        self.assertIn('agent, "MISSING") == "DISABLED"', detector)
        self.assertIn('setting.Status == "DISABLED"', detector)

    @unittest.skipUnless(os.environ.get("SECURITY_TEST_TERRAFORM"), "optional native HCL fixture check; SDK-free static guard runs above")
    def test_actual_guardduty_nested_expression_rejects_enabled_missing_malformed_agents(self):
        detector = block(REGIONAL, "aws_cloudcontrolapi_resource", "guardduty")
        conditions = re.findall(r'postcondition\s*\{\s*condition\s*=(.*?)\n\s*error_message\s*=\s*"([^"]+)"', detector, re.S)
        expression = next(value for value, message in conditions if message.startswith("GuardDuty nested"))
        agents = json.loads(re.search(r'guardduty_runtime_agents\s*=\s*(\[[^]]+\])', REGIONAL).group(1))
        good = {"Features": [{"Name": "RUNTIME_MONITORING", "Status": "DISABLED", "AdditionalConfiguration": [
            {"Name": name, "Status": "DISABLED"} for name in agents]}]}
        fixtures = [("all disabled", good, True)]
        for agent in agents:
            bad = copy.deepcopy(good)
            next(setting for setting in bad["Features"][0]["AdditionalConfiguration"] if setting["Name"] == agent)["Status"] = "ENABLED"
            fixtures.append((agent + " enabled", bad, False))
        for label, settings in (("missing one", good["Features"][0]["AdditionalConfiguration"][:-1]),
                                ("missing all", []), ("malformed", None),
                                ("unknown enabled", good["Features"][0]["AdditionalConfiguration"] + [{"Name": "NEW_AGENT", "Status": "ENABLED"}])):
            bad = copy.deepcopy(good)
            bad["Features"][0]["AdditionalConfiguration"] = settings
            fixtures.append((label, bad, False))
        with tempfile.TemporaryDirectory(prefix="security-expression-") as directory:
            for label, properties, expected in fixtures:
                with self.subTest(case=label):
                    rendered = expression.replace("local.guardduty_runtime_agents", json.dumps(agents)).replace("self.properties", json.dumps(json.dumps(properties)))
                    result = subprocess.run([os.environ["SECURITY_TEST_TERRAFORM"], "console", "-no-color"],
                        input=" ".join(rendered.splitlines()) + "\n", text=True, capture_output=True, timeout=15, cwd=directory,
                        env={"CHECKPOINT_DISABLE": "1", "TF_CLI_CONFIG_FILE": "/dev/null", "TF_IN_AUTOMATION": "1"})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), str(expected).lower())

    def test_kms_and_backup_tampering_alert_without_routine_cleanup_noise(self):
        pattern = block(REGIONAL, "aws_cloudwatch_event_rule", "findings")
        def names_for(source):
            match = re.search(r'eventSource\s*=\s*\["' + re.escape(source) +
                              r'"\]\s*eventName\s*=\s*\[([^]]+)\]', pattern)
            self.assertIsNotNone(match)
            return set(re.findall(r'"([^"]+)"', match.group(1)))
        self.assertEqual(names_for("kms.amazonaws.com"),
                         {"DisableKey", "ScheduleKeyDeletion", "PutKeyPolicy", "DisableKeyRotation"})
        self.assertEqual(names_for("backup.amazonaws.com"),
                         {"DeleteBackupVault", "DeleteBackupPlan", "DeleteBackupSelection", "UpdateBackupPlan",
                          "PutBackupVaultAccessPolicy", "DeleteBackupVaultAccessPolicy",
                          "PutBackupVaultLockConfiguration", "DeleteBackupVaultLockConfiguration",
                          "UpdateRecoveryPointLifecycle", "UpdateGlobalSettings", "UpdateRegionSettings"})
        deletion = re.search(r'eventName\s*=\s*\["DeleteRecoveryPoint"\]\s*'
                             r'requestParameters\s*=\s*\{\s*backupVaultName\s*=\s*\[([^]]+)\]', pattern)
        self.assertIsNotNone(deletion)
        self.assertEqual(set(re.findall(r'"([^"]+)"', deletion.group(1))),
                         {"ejc3-backup", "ejc3-backup-dr", "fcvm-backups", "ejc3-backup-recovery"})

    def test_all_regional_modules_and_watchdog_coverage_agree(self):
        modules = set(re.findall(r'^module "(security_(?:main|staging)_[^"]+)"', TERRAFORM, re.M))
        self.assertEqual(modules, {"security_" + account + "_" + region.replace("-", "_")
                                  for account in ("main", "staging") for region in REGIONS})
        schedule = block(TERRAFORM, "aws_cloudwatch_event_target", "security_delivery_health")
        for module in modules:
            self.assertIn("module." + module, schedule)

    def test_dlqs_are_regional_encrypted_bounded_and_source_pinned(self):
        for source, queue in ((REGIONAL, "delivery_failures"), (TERRAFORM, "security_delivery_failures")):
            queue_block = block(source, "aws_sqs_queue", queue)
            self.assertIn("1209600", queue_block)
            self.assertRegex(queue_block, r"sqs_managed_sse_enabled\s*=\s*true")
            policy = block(source, "aws_sqs_queue_policy", queue)
            self.assertIn('"sqs:SendMessage"', policy)
            self.assertIn('"aws:SourceArn"', policy)
            self.assertIn('"aws:SecureTransport"', policy)
            self.assertIn('"aws:PrincipalIsAWSService"', policy)
        for source, target in ((REGIONAL, "central"), (TERRAFORM, "security_notify"), (TERRAFORM, "security_delivery_health")):
            self.assertIn("dead_letter_config", block(source, "aws_cloudwatch_event_target", target))

    def test_failure_alarms_trigger_on_one_failure_and_missing_pulses_alarm(self):
        gauges = block(TERRAFORM, "aws_cloudwatch_metric_alarm", "security_delivery")
        self.assertIn('"FailedDeliveries", "QueuedEvents", "ObserverErrors"', gauges)
        self.assertRegex(gauges, r"threshold\s*=\s*1\b")
        self.assertRegex(gauges, r"evaluation_periods\s*=\s*1\b")
        heartbeat = block(TERRAFORM, "aws_cloudwatch_metric_alarm", "security_delivery_heartbeat")
        self.assertIn('"FILL(pulse, 0)"', heartbeat)
        self.assertRegex(heartbeat, r"period\s*=\s*300\b")
        self.assertRegex(heartbeat, r"evaluation_periods\s*=\s*3\b")
        self.assertRegex(heartbeat, r"datapoints_to_alarm\s*=\s*3\b")
        self.assertRegex(heartbeat, r'treat_missing_data\s*=\s*"breaching"')
        self.assertIn('"LessThanThreshold"', heartbeat)
        self.assertRegex(heartbeat, r"threshold\s*=\s*1\b")

    def test_observer_is_read_only_except_own_logs_and_health_metrics(self):
        main = block(TERRAFORM, "aws_iam_role_policy", "security_delivery_health")
        staging = block(TERRAFORM, "aws_iam_role_policy", "security_delivery_observer_staging")
        for policy in (main, staging):
            self.assertNotIn("AdministratorAccess", policy)
            self.assertNotIn("sqs:ReceiveMessage", policy)
            self.assertNotIn("sqs:DeleteMessage", policy)
            self.assertNotIn("sqs:PurgeQueue", policy)
            self.assertIn('"sqs:GetQueueAttributes"', policy)
            self.assertIn('"cloudwatch:GetMetricData"', policy)
            self.assertIn('"events:DescribeRule", "events:ListTargetsByRule"', policy)
            self.assertIn(':rule/security-forward-findings', policy)
            self.assertNotIn('"events:Put', policy)
        self.assertIn('aws_cloudwatch_event_rule.security_notify.arn', main)
        self.assertIn('aws_cloudwatch_event_rule.security_delivery_health.arn', main)
        self.assertNotIn('"sts:AssumeRole"', staging)
        self.assertIn('"cloudwatch:namespace" = "SecurityDelivery"', main)
        role = block(TERRAFORM, "aws_iam_role", "security_delivery_observer_staging")
        self.assertIn("AWS = aws_iam_role.security_delivery_health.arn", role)

    def test_runtime_and_log_retention_remain_bounded(self):
        function = block(TERRAFORM, "aws_lambda_function", "security_delivery_health")
        self.assertRegex(function, r"timeout\s*=\s*90\b")
        self.assertRegex(function, r"reserved_concurrent_executions\s*=\s*1\b")
        self.assertRegex(block(TERRAFORM, "aws_cloudwatch_log_group", "security_delivery_health"),
                         r"retention_in_days\s*=\s*30\b")
        self.assertIn('schedule_expression = "rate(5 minutes)"', block(TERRAFORM, "aws_cloudwatch_event_rule", "security_delivery_health"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
