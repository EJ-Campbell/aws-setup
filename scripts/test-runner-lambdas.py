#!/usr/bin/env python3
"""Exercise the runner Lambdas' launch and queue-scan logic against fakes.

Why this exists: both Lambdas live as inline Python inside `runner-autoscale.tf`,
so nothing runs them before they are deployed. On 2026-08-07 that cost hours of
queued CI -- the x86 launcher retried one instance type forever because AWS
reports a spot capacity failure asynchronously and the fallback loop only
advanced on an exception, and the queue poll sampled five workflow runs when six
undrainable phantom runs were sitting at the head of the list.

This extracts the real heredoc bodies out of `runner-autoscale.tf` rather than
keeping a copy that can drift, and runs them with boto3, urllib and the clock
replaced by fakes. No AWS or GitHub credentials, and no network.

Run from the repo root:  python3 scripts/test-runner-lambdas.py
Exit code 1 if any case fails.
"""
import json
import re
import sys
import textwrap
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

TF_FILE = Path(__file__).resolve().parent.parent / "runner-autoscale.tf"
NOW = datetime(2026, 8, 7, 20, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Loading the Lambda source out of the Terraform heredocs
# --------------------------------------------------------------------------

def extract_lambda_sources():
    """The two `content = <<-EOF ... EOF` bodies, in file order.

    Terraform strips the indentation of the least-indented line from a `<<-`
    heredoc, which is exactly what textwrap.dedent does, so the text handed to
    exec() here is byte-identical to the lambda_function.py that gets zipped.
    """
    lines = TF_FILE.read_text().splitlines()
    sources, body, collecting = [], [], False
    for line in lines:
        if collecting:
            if line.strip() == "EOF":
                sources.append(textwrap.dedent("\n".join(body)))
                body, collecting = [], False
            else:
                body.append(line)
        elif re.match(r"^\s*content\s*=\s*<<-EOF\s*$", line):
            collecting = True
    return sources


class FakeEC2:
    """Just enough EC2 to drive the launcher and the reaper."""

    def __init__(self, instances=(), run_instances_errors=None):
        self.instances = list(instances)
        self.run_instances_errors = run_instances_errors or {}
        self.calls = []

    def _matches(self, instance, filters):
        for f in filters:
            name, values = f["Name"], f["Values"]
            if name == "instance-state-name":
                if instance["State"]["Name"] not in values:
                    return False
            elif name.startswith("tag:"):
                key = name.split(":", 1)[1]
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                if tags.get(key) not in values:
                    return False
        return True

    def describe_instances(self, **kw):
        self.calls.append(("describe_instances", kw))
        matched = [i for i in self.instances if self._matches(i, kw.get("Filters", []))]
        return {"Reservations": [{"Instances": matched}] if matched else []}

    def describe_images(self, **kw):
        self.calls.append(("describe_images", kw))
        return {"Images": [{"ImageId": "ami-test", "CreationDate": "2026-08-01T00:00:00Z"}]}

    def run_instances(self, **kw):
        self.calls.append(("run_instances", kw))
        error = self.run_instances_errors.get(kw["InstanceType"])
        if error:
            raise Exception(error)
        return {"Instances": [{"InstanceId": f"i-new-{kw['InstanceType']}"}]}

    def create_tags(self, **kw):
        self.calls.append(("create_tags", kw))

    def terminate_instances(self, **kw):
        self.calls.append(("terminate_instances", kw))

    def ops(self, name):
        return [kw for op, kw in self.calls if op == name]


class FakeSSM:
    def __init__(self, pat="ghp_test"):
        self.pat = pat

    def get_parameter(self, **kw):
        if kw["Name"].endswith("/pat"):
            return {"Parameter": {"Value": self.pat}}
        return {"Parameter": {"Value": "IyEvYmluL2Jhc2gK"}}


class FakeLambdaClient:
    def __init__(self):
        self.invokes = []

    def invoke(self, **kw):
        self.invokes.append(json.loads(json.loads(kw["Payload"])["body"]))

    def arch_invokes(self):
        counts = {}
        for payload in self.invokes:
            labels = [x.lower() for x in payload["workflow_job"]["labels"]]
            arch = "x86_64" if "x64" in labels else "arm64"
            counts[arch] = counts.get(arch, 0) + 1
        return counts


class FakeGitHub:
    """Routes GitHub REST URLs to canned JSON, honouring status and page."""

    def __init__(self, runs=(), jobs=None, runners=()):
        self.runs = list(runs)
        self.jobs = jobs or {}
        self.runners = list(runners)
        self.requests = []

    def _payload(self, url):
        self.requests.append(url)
        page_match = re.search(r"[?&]page=(\d+)", url)
        per_page_match = re.search(r"per_page=(\d+)", url)
        page = int(page_match.group(1)) if page_match else 1
        per_page = int(per_page_match.group(1)) if per_page_match else 30
        if "/actions/runners" in url:
            return {"runners": self.runners}
        jobs_match = re.search(r"/actions/runs/(\d+)/jobs", url)
        if jobs_match:
            jobs = self.jobs.get(int(jobs_match.group(1)), [])
            window = jobs[(page - 1) * per_page: page * per_page]
            return {"total_count": len(jobs), "jobs": window}
        status = re.search(r"[?&]status=(\w+)", url).group(1)
        matched = [r for r in self.runs if r["status"] == status]
        window = matched[(page - 1) * per_page: page * per_page]
        return {"total_count": len(matched), "workflow_runs": window}

    def as_urllib(self):
        github = self

        class Response:
            def __init__(self, data):
                self.data = json.dumps(data).encode()

            def read(self):
                return self.data

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        module = types.SimpleNamespace()
        module.request = types.SimpleNamespace(
            Request=lambda url, **kw: url,
            urlopen=lambda url, **kw: Response(github._payload(url)),
        )
        return module


def load_lambda(source, ec2, ssm, lambda_client=None, github=None, env=None, now=NOW):
    """exec the Lambda source with its AWS and GitHub edges replaced."""
    clients = {"ec2": ec2, "ssm": ssm, "lambda": lambda_client}
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.client = lambda service, **kw: clients[service]
    sys.modules["boto3"] = fake_boto3

    namespace = {"__name__": "lambda_function"}
    exec(compile(source, "<lambda_function.py>", "exec"), namespace)

    if github is not None:
        namespace["urllib"] = github.as_urllib()
    namespace["os"].environ.update({
        "SUBNET_ID": "subnet-test",
        "SECURITY_GROUP_ID": "sg-test",
        "INSTANCE_PROFILE": "runner-profile",
        "USER_DATA_PARAM": "/github-runner/user-data",
        "WEBHOOK_FUNCTION": "github-runner-webhook",
        "MAX_RUNNERS": "4",
        **(env or {}),
    })

    # Freeze the clock so "stalled for 20 minutes" is a fact, not a race.
    class FixedDatetime(namespace["datetime"]):
        @classmethod
        def now(cls, tz=None):
            return now

    namespace["datetime"] = FixedDatetime
    return namespace


def instance(instance_id, instance_type, state, age_minutes, arch="x86_64", tags=None,
             state_reason=None):
    all_tags = {"Role": "github-runner", "Name": f"github-runner-{arch}"}
    all_tags.update(tags or {})
    record = {
        "InstanceId": instance_id,
        "InstanceType": instance_type,
        "State": {"Name": state},
        "LaunchTime": NOW - timedelta(minutes=age_minutes),
        "Tags": [{"Key": k, "Value": v} for k, v in all_tags.items()],
    }
    if state_reason:
        record["StateReason"] = {"Code": state_reason}
    return record


def run(run_id, status):
    return {"id": run_id, "status": status}


def job(status, arch, name="job"):
    labels = ["self-hosted", "Linux", "X64" if arch == "x86_64" else "ARM64"]
    return {"name": name, "status": status, "labels": labels}


# --------------------------------------------------------------------------
# Cases: the x86 spot fallback
# --------------------------------------------------------------------------

def webhook(ec2, **kw):
    return load_lambda(WEBHOOK_SRC, ec2, FakeSSM(), **kw)


def launched_types(ec2):
    return [kw["InstanceType"] for kw in ec2.ops("run_instances")]


def case_aws_capacity_verdict_advances_the_type():
    """AWS's own state reason on a dead instance moves the launcher along."""
    ec2 = FakeEC2([instance("i-dead", "c5d.metal", "terminated", 60,
                            state_reason="Server.InsufficientInstanceCapacity")])
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == ["c5.metal"], launched_types(ec2)


def case_stalled_pending_launch_advances_the_type():
    """A launch still pending past the startup window is a capacity failure."""
    ec2 = FakeEC2([instance("i-stuck", "c5d.metal", "pending", 20)])
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == ["c5.metal"], launched_types(ec2)


def case_capacity_failed_tag_advances_the_type():
    """The tag the cleanup Lambda stamps survives the instance's termination."""
    ec2 = FakeEC2([instance("i-reaped", "c5d.metal", "terminated", 30,
                            tags={"CapacityFailedAt": NOW.isoformat()})])
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == ["c5.metal"], launched_types(ec2)


def case_pending_inside_the_startup_window_is_not_a_failure():
    """A metal instance that is merely still booting must not rotate the list."""
    ec2 = FakeEC2([instance("i-booting", "c5d.metal", "pending", 5)])
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == ["c5d.metal"], launched_types(ec2)


def case_every_type_failed_still_launches():
    """Deprioritising must never empty the list."""
    dead = [instance(f"i-{t}", t, "terminated", 10, state_reason="Server.InsufficientInstanceCapacity")
            for t in ("c5d.metal", "c5.metal", "c6i.metal", "m5d.metal")]
    ec2 = FakeEC2(dead)
    module = webhook(ec2)
    order = module["get_instance_types"]("x86_64", {"c5d.metal", "c5.metal", "c6i.metal", "m5d.metal"})
    assert sorted(order) == sorted(["c5d.metal", "c5.metal", "c6i.metal", "m5d.metal"]), order
    module["launch_runner"]("x86_64")
    assert launched_types(ec2) == ["c5d.metal"], launched_types(ec2)


def case_synchronous_exception_still_falls_through():
    """The original exception path still advances when AWS does raise."""
    ec2 = FakeEC2(run_instances_errors={"c5d.metal": "InsufficientInstanceCapacity"})
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == ["c5d.metal", "c5.metal"], launched_types(ec2)


def case_incident_replay_three_dead_c5d_launches():
    """2026-08-07: three c5d.metal launches at 18:41, 18:46 and 18:51.

    All three returned an instance ID, none reached `running`, and AWS did not
    report instance-terminated-no-capacity until 20:31. The old loop saw no
    exception, so every retry picked c5d.metal again and c5.metal, c6i.metal and
    m5d.metal were never tried.
    """
    ec2 = FakeEC2([
        instance("i-001e64c56eb71053b", "c5d.metal", "pending", 79),
        instance("i-012093644a97c1b37", "c5d.metal", "pending", 74),
        instance("i-00ead8c13e0bfffff", "c5d.metal", "pending", 69),
    ])
    module = webhook(ec2)
    module["launch_runner"]("x86_64")
    assert launched_types(ec2) == ["c5.metal"], launched_types(ec2)
    # And the husks are not counted as runners, so the pool is not "full".
    assert module["get_running_runners"]("x86_64") == 0


def case_ordinary_spot_reclaim_does_not_rotate():
    """A reclaimed runner is not a failed launch.

    Server.SpotInstanceTermination covers a runner that worked for an hour and was
    taken back. Rotating on it would send ARM to c7g.metal, which has no
    instance-store NVMe, so user_data never builds /mnt/fcvm-btrfs.
    """
    ec2 = FakeEC2([instance("i-reclaimed", "c7gd.metal", "terminated", 90, arch="arm64",
                            state_reason="Server.SpotInstanceTermination")])
    webhook(ec2)["launch_runner"]("arm64")
    assert launched_types(ec2) == ["c7gd.metal"], launched_types(ec2)


def case_arm_is_unaffected():
    ec2 = FakeEC2([instance("i-ok", "c7gd.metal", "running", 30, arch="arm64")])
    webhook(ec2)["launch_runner"]("arm64")
    assert launched_types(ec2) == ["c7gd.metal"], launched_types(ec2)


def case_one_arch_failure_does_not_rotate_the_other():
    """x86 instances must not deprioritise an ARM type, or vice versa."""
    ec2 = FakeEC2([instance("i-x", "c5d.metal", "pending", 40, arch="x86_64")])
    webhook(ec2)["launch_runner"]("arm64")
    assert launched_types(ec2) == ["c7gd.metal"], launched_types(ec2)


# --------------------------------------------------------------------------
# Cases: the cleanup Lambda's reaper and queue scan
# --------------------------------------------------------------------------

def cleanup(ec2, github, lambda_client=None, env=None):
    return load_lambda(CLEANUP_SRC, ec2, FakeSSM(), lambda_client or FakeLambdaClient(),
                       github, env)


def case_stalled_launch_is_tagged_then_terminated():
    """The tag has to land before the terminate, or the reason is lost."""
    ec2 = FakeEC2([instance("i-stuck", "c5d.metal", "pending", 30)])
    result = cleanup(ec2, FakeGitHub())["handler"]({}, None)
    assert result["stalled_launches"] == ["i-stuck"], result
    ops = [op for op, _ in ec2.calls if op in ("create_tags", "terminate_instances")]
    assert ops == ["create_tags", "terminate_instances"], ops
    tags = {t["Key"]: t["Value"] for t in ec2.ops("create_tags")[0]["Tags"]}
    assert tags["CapacityFailedAt"] == NOW.isoformat(), tags


def case_young_pending_launch_is_left_alone():
    ec2 = FakeEC2([instance("i-booting", "c5d.metal", "pending", 5)])
    result = cleanup(ec2, FakeGitHub())["handler"]({}, None)
    assert result["stalled_launches"] == [], result
    assert ec2.ops("terminate_instances") == []


def poll(github, env=None):
    """Run one cleanup poll and report what it asked the webhook to launch."""
    invoker = FakeLambdaClient()
    cleanup(FakeEC2(), github, invoker, env)["handler"]({}, None)
    return invoker.arch_invokes()


def case_real_work_behind_six_phantom_runs_is_found():
    """The six 2026-08-06 phantoms are newer than the real run and have no jobs.

    The runs endpoint returns newest first, so the phantoms fill the whole
    five-run sample and the real run is never reached. Driven through handler so
    the assertion is about runners launched, not about an internal helper.
    """
    phantoms = [run(31127540655 - i, "queued") for i in range(6)]
    real = run(31000000000, "queued")
    github = FakeGitHub(
        runs=phantoms + [real],
        jobs={real["id"]: [job("queued", "arm64"), job("queued", "arm64")],
              **{p["id"]: [] for p in phantoms}},
    )
    sample = github._payload("https://api.github.com/repos/x/actions/runs?status=queued&per_page=10")
    assert [r["id"] for r in sample["workflow_runs"]][:5] == [p["id"] for p in phantoms[:5]], \
        "the phantoms must occupy the whole old sample for this case to mean anything"
    assert poll(github) == {"arm64": 2}, poll(github)


def case_queued_jobs_in_an_in_progress_run_are_found():
    """Run 31202629167 held arm64 jobs queued for 45m while it was in_progress.

    status=queued never returns such a run, so its queued jobs were invisible.
    """
    live = run(31202629167, "in_progress")
    github = FakeGitHub(runs=[live], jobs={live["id"]: [
        job("in_progress", "arm64"), job("queued", "arm64"), job("queued", "x86_64"),
    ]})
    assert poll(github) == {"arm64": 1, "x86_64": 1}, poll(github)


def case_jobs_beyond_the_first_page_are_found():
    """A run with more jobs than one page must not hide the queued ones."""
    big = run(42, "queued")
    jobs = [job("completed", "arm64") for _ in range(100)] + [job("queued", "x86_64")]
    github = FakeGitHub(runs=[big], jobs={big["id"]: jobs})
    assert poll(github) == {"x86_64": 1}, poll(github)


def case_runs_beyond_the_first_page_are_found():
    """Real work sitting past the first page of runs must still be counted."""
    runs = [run(200000 - i, "queued") for i in range(101)]
    jobs = {r["id"]: [] for r in runs}
    jobs[runs[-1]["id"]] = [job("queued", "x86_64")]
    assert poll(FakeGitHub(runs=runs, jobs=jobs)) == {"x86_64": 1}


def case_queue_deeper_than_the_pool_launches_up_to_the_cap():
    """Seven queued arm64 jobs must fill the pool in one poll, not one per poll."""
    busy = run(7, "queued")
    github = FakeGitHub(runs=[busy], jobs={busy["id"]: [job("queued", "arm64") for _ in range(7)]})
    assert poll(github) == {"arm64": 4}, poll(github)


def case_phantom_only_queue_launches_nothing():
    phantoms = [run(31127540655 - i, "queued") for i in range(6)]
    github = FakeGitHub(runs=phantoms, jobs={p["id"]: [] for p in phantoms})
    assert poll(github) == {}, poll(github)


def case_scan_stops_once_both_architectures_are_saturated():
    """Saturation is the only early exit, and it cannot change the outcome."""
    runs = [run(900 - i, "queued") for i in range(20)]
    jobs = {r["id"]: [job("queued", "arm64")] * 4 + [job("queued", "x86_64")] * 4 for r in runs}
    github = FakeGitHub(runs=runs, jobs=jobs)
    module = cleanup(FakeEC2(), github)
    demand = module["queued_demand"]("ghp_test", 4)
    assert demand == {"arm64": 4, "x86_64": 4}, demand
    job_calls = [u for u in github.requests if "/jobs" in u]
    assert len(job_calls) == 1, f"scanned {len(job_calls)} runs after saturation"


def case_only_self_hosted_jobs_count():
    hosted = run(11, "queued")
    github = FakeGitHub(runs=[hosted], jobs={hosted["id"]: [
        {"name": "Lint", "status": "queued", "labels": ["ubuntu-latest"]},
    ]})
    demand = cleanup(FakeEC2(), github)["queued_demand"]("ghp_test", 4)
    assert demand == {"arm64": 0, "x86_64": 0}, demand


CASES = [v for k, v in sorted(globals().items()) if k.startswith("case_")]


def main():
    global WEBHOOK_SRC, CLEANUP_SRC
    sources = extract_lambda_sources()
    if len(sources) != 2:
        print(f"FAIL: expected 2 Lambda heredocs in {TF_FILE.name}, found {len(sources)}")
        return 1
    WEBHOOK_SRC, CLEANUP_SRC = sources

    failures = 0
    for case in CASES:
        try:
            case()
            print(f"ok   {case.__name__}")
        except Exception as e:
            failures += 1
            print(f"FAIL {case.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
