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
import contextlib
import io
import json
import os
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

    def __init__(self, instances=(), run_instances_errors=None, terminate_error=None,
                 lookup_error=None, journal=None):
        self.instances = list(instances)
        self.run_instances_errors = run_instances_errors or {}
        # TerminateInstances rejected: an IAM change, DisableApiTermination, a
        # transient 5xx. The instance stays alive, so a poll that reports success
        # here would be claiming the fleet's lifetime bound took effect when it
        # did not.
        self.terminate_error = terminate_error
        # DescribeInstances(InstanceIds=...) failing. Distinct from "no such
        # instance": one is "could not ask", the other is "it is gone", and the
        # orphan phase deregisters on the second.
        self.lookup_error = lookup_error
        # Optional list shared with FakeGitHub, so the ORDER of AWS and GitHub work
        # within one invocation can be asserted. Phase order is a safety property
        # here: a Lambda timeout is not catchable, so anything unbounded that runs
        # ahead of the age sweep can stop the sweep happening at all.
        self.journal = journal if journal is not None else []
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
        if "InstanceIds" in kw and self.lookup_error:
            raise self.lookup_error
        matched = [i for i in self.instances if self._matches(i, kw.get("Filters", []))]
        # get_instance_state() looks an instance up by id with no filters. Without
        # honouring InstanceIds every lookup would answer with the first instance in
        # the list, so a case about one runner would silently be answered by another.
        if "InstanceIds" in kw:
            matched = [i for i in matched if i["InstanceId"] in kw["InstanceIds"]]
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
        self.journal.append(f"ec2:create_tags:{','.join(kw['Resources'])}")
        # An accepted CreateTags has to be visible to the NEXT describe_instances,
        # for the same reason an accepted terminate has to move the instance: a
        # case that spans two polls would otherwise assert against a world in
        # which nothing the Lambda wrote ever happened. LeaseExpires,
        # RunnerSeenAt and LeaseRenewedAt are written on one poll and read back
        # on a later one.
        for inst in self.instances:
            if inst.get("InstanceId") in kw["Resources"]:
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                tags.update({t["Key"]: t["Value"] for t in kw["Tags"]})
                inst["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]

    def terminate_instances(self, **kw):
        self.calls.append(("terminate_instances", kw))
        self.journal.append(f"ec2:terminate:{','.join(kw['InstanceIds'])}")
        if self.terminate_error:
            raise self.terminate_error
        # An accepted terminate MOVES the instance. Leaving it 'running' let a case
        # assert an outcome that only held because the fake froze the world: later
        # phases in the same poll see 'shutting-down' in reality, not 'running'.
        for inst in self.instances:
            if inst.get("InstanceId") in kw["InstanceIds"]:
                inst["State"] = {"Name": "shutting-down"}

    def ops(self, name):
        return [kw for op, kw in self.calls if op == name]


class FakeClientError(Exception):
    """Shaped like botocore's ClientError, which carries its code in .response.

    The Lambda cannot import botocore (it is present in the runtime, but the
    handler only ever sees the exception), so it reads the code off the object.
    """

    def __init__(self, code, message="fake"):
        super().__init__(f"An error occurred ({code}): {message}")
        self.response = {"Error": {"Code": code, "Message": message}}


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
        """Total runners REQUESTED per architecture.

        The cleanup poll sends one invocation per architecture whose payload
        carries the whole deficit as launch_count (a burst of single-launch
        invocations could overshoot MAX_RUNNERS: DescribeInstances is eventually
        consistent, so each invocation can miss the instance the previous one
        just launched). Summing launch_count keeps these assertions about
        demand, and invocations_per_arch() below asserts the one-invoke shape.
        """
        counts = {}
        for payload in self.invokes:
            labels = [x.lower() for x in payload["workflow_job"]["labels"]]
            arch = "x86_64" if "x64" in labels else "arm64"
            counts[arch] = counts.get(arch, 0) + payload.get("launch_count", 1)
        return counts

    def invocations_per_arch(self):
        counts = {}
        for payload in self.invokes:
            labels = [x.lower() for x in payload["workflow_job"]["labels"]]
            arch = "x86_64" if "x64" in labels else "arm64"
            counts[arch] = counts.get(arch, 0) + 1
        return counts


class FakeGitHub:
    """Routes GitHub REST URLs to canned JSON, honouring status and page."""

    def __init__(self, runs=(), jobs=None, runners=(), runners_error=False,
                 delete_error=False, recheck=None, journal=None, runners_total=None,
                 runner_payloads=None):
        self.runs = list(runs)
        self.jobs = jobs or {}
        self.runners = list(runners)
        # Every /actions/runners call raises: a PAT that lost its scope, a 5xx, a
        # rate limit. get_runners() turns it into an unread roster, so the reaper
        # has no actionable record for any instance - the state a decision must
        # survive.
        self.runners_error = runners_error
        # A deregistration that fails must never stop a termination.
        self.delete_error = delete_error
        # What GET /actions/runners/{id} answers, when that must differ from the
        # list this poll already read: {runner_id: record or None-to-fail}.
        self.recheck = recheck or {}
        # What the roster CLAIMS is registered, when that must differ from what it
        # hands back: a page shorter than total_count is a truncated read, and it
        # is indistinguishable from "that runner is not registered" to anything
        # that does not compare the two.
        self.runners_total = runners_total
        # Exact successive list payloads, when pagination itself is the input
        # under test. This can model a roster changing between complete reads or
        # a page boundary shifting under concurrent registration/deregistration.
        # Once exhausted, the last payload remains the answer so later phases do
        # not get an unrelated fake failure.
        self.runner_payloads = list(runner_payloads) if runner_payloads is not None else None
        self.runner_payload_index = 0
        self.journal = journal if journal is not None else []
        self.requests = []
        self.deletes = []

    def _payload(self, req):
        url = getattr(req, "url", req)
        method = getattr(req, "method", None)
        self.requests.append(url)
        self.journal.append(f"github:{method or 'GET'}:{url.split('/repos/ejc3/fcvm')[-1]}")
        if method == "DELETE":
            self.deletes.append(url)
            if self.delete_error:
                raise OSError("GitHub refused the deregistration")
            # Deregistration REMOVES the runner, and a second DELETE for the same id
            # 404s. Without that, a case could not tell "cleaned one orphan" from
            # "deregistered the same runner twice".
            gone = int(url.rsplit("/", 1)[-1])
            before = len(self.runners)
            self.runners = [r for r in self.runners if r.get("id") != gone]
            if len(self.runners) == before:
                raise OSError("HTTP Error 404: Not Found")
            return {}
        page_match = re.search(r"[?&]page=(\d+)", url)
        per_page_match = re.search(r"per_page=(\d+)", url)
        page = int(page_match.group(1)) if page_match else 1
        per_page = int(per_page_match.group(1)) if per_page_match else 30
        one_runner = re.search(r"/actions/runners/(\d+)$", url)
        if one_runner:
            record = self.recheck.get(int(one_runner.group(1)), "unset")
            if record == "unset":
                record = next((r for r in self.runners
                               if r.get("id") == int(one_runner.group(1))), None)
            if record is None:
                raise OSError("GitHub is unreachable")
            return record
        if "/actions/runners" in url:
            if self.runners_error:
                raise OSError("GitHub is unreachable")
            if self.runner_payloads:
                index = min(self.runner_payload_index, len(self.runner_payloads) - 1)
                self.runner_payload_index += 1
                return self.runner_payloads[index]
            window = self.runners[(page - 1) * per_page: page * per_page]
            total = len(self.runners) if self.runners_total is None else self.runners_total
            return {"total_count": total, "runners": window}
        jobs_match = re.search(r"/actions/runs/(\d+)/jobs", url)
        if jobs_match:
            jobs = self.jobs.get(int(jobs_match.group(1)), [])
            window = jobs[(page - 1) * per_page: page * per_page]
            return {"total_count": len(jobs), "jobs": window}
        status_match = re.search(r"[?&]status=(\w+)", url)
        if not status_match:
            # Fail LOUDLY: the Lambdas wrap GitHub calls in broad except blocks,
            # so a silently unrouted URL would read as "no demand" and pass.
            raise ValueError(f"FakeGitHub has no route for {url}")
        status = status_match.group(1)
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

        # Request objects carry the method so a DELETE (deregistration) is
        # distinguishable from a GET at the point urlopen is actually called.
        class Req:
            def __init__(self, url, method=None):
                self.url = url
                self.method = method

        module = types.SimpleNamespace()
        module.request = types.SimpleNamespace(
            Request=lambda url, **kw: Req(url, kw.get("method")),
            urlopen=lambda req, **kw: Response(github._payload(req)),
        )
        return module


_BASE_ENV = dict(os.environ)



def capture_emf(emit, **kwargs):
    """Run emit_decision and return the EMF dict it printed."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        emit(**kwargs)
    return json.loads(buf.getvalue().strip().splitlines()[-1])


def load_lambda(source, ec2, ssm, lambda_client=None, github=None, env=None, now=NOW):
    """exec the Lambda source with its AWS and GitHub edges replaced.

    os.environ is reset to the process baseline first: exec does not isolate
    imports, so the env vars below land in the REAL environment and would
    otherwise leak between cases (a WEBHOOK_SECRET set by one case must not
    still be set for the next).
    """
    os.environ.clear()
    os.environ.update(_BASE_ENV)
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
    #
    # The tz argument is honoured rather than ignored: every Lambda call site
    # passes timezone.utc, and one that stopped would start comparing a naive
    # clock against boto3's aware LaunchTime. A fake that returns an aware value
    # either way hides that, so `now()` with no tz returns naive here exactly as
    # the real datetime does.
    class FixedDatetime(namespace["datetime"]):
        @classmethod
        def now(cls, tz=None):
            return now if tz is not None else now.replace(tzinfo=None)

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


def type_order(arch="x86_64"):
    """The launcher's own list, so these cases follow it instead of pinning it.

    Pinned copies went stale the moment the storeless types were removed.
    """
    return webhook(FakeEC2([]))["get_instance_types"](arch)


def case_aws_capacity_verdict_advances_the_type():
    """AWS's own state reason on a dead instance moves the launcher along."""
    ec2 = FakeEC2([instance("i-dead", "c5d.metal", "terminated", 60,
                            state_reason="Server.InsufficientInstanceCapacity")])
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == [type_order()[1]], launched_types(ec2)


def case_stalled_pending_launch_advances_the_type():
    """A launch still pending past the startup window is a capacity failure."""
    ec2 = FakeEC2([instance("i-stuck", "c5d.metal", "pending", 20)])
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == [type_order()[1]], launched_types(ec2)


def case_capacity_failed_tag_advances_the_type():
    """The tag the cleanup Lambda stamps survives the instance's termination."""
    ec2 = FakeEC2([instance("i-reaped", "c5d.metal", "terminated", 30,
                            tags={"CapacityFailedAt": NOW.isoformat()})])
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == [type_order()[1]], launched_types(ec2)


def case_pending_inside_the_startup_window_is_not_a_failure():
    """A metal instance that is merely still booting must not rotate the list."""
    ec2 = FakeEC2([instance("i-booting", "c5d.metal", "pending", 5)])
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == ["c5d.metal"], launched_types(ec2)


def case_every_type_failed_still_launches():
    """Deprioritising must never empty the list."""
    module = webhook(FakeEC2([]))
    every = module["get_instance_types"]("x86_64")
    dead = [instance(f"i-{t}", t, "terminated", 10, state_reason="Server.InsufficientInstanceCapacity")
            for t in every]
    ec2 = FakeEC2(dead)
    module = webhook(ec2)
    order = module["get_instance_types"]("x86_64", set(every))
    assert sorted(order) == sorted(every), order
    module["launch_runner"]("x86_64")
    assert launched_types(ec2) == [every[0]], launched_types(ec2)


def case_every_launchable_type_has_instance_storage():
    """A storeless type is unusable to THIS bootstrap, so do not launch one.

    user_data builds /mnt/fcvm-btrfs only from instance-store NVMe. fcvm itself
    does not need instance store (setup falls back to a loopback btrfs image,
    src/setup/storage.rs); what it requires is btrfs, for reflink CoW. So the
    constraint is the bootstrap's, and holds until user_data grows that
    fallback. On 2026-08-15 a c7g.metal spot instance came up, died in
    user_data with no disk to find, never registered, and billed while jobs
    queued -- while c5.metal and c6i.metal sat in the x86 list with the same
    defect.

    AWS marks instance storage with a 'd' in the family (c5d, m5d, c7gd,
    m6id). Confirm any addition for real with:
      aws ec2 describe-instance-types --instance-types <t> \
        --query 'InstanceTypes[].InstanceStorageSupported'
    """
    module = webhook(FakeEC2([]))
    for arch in ("x86_64", "arm64"):
        types = module["get_instance_types"](arch)
        assert types, f"{arch} has no launchable types"
        for t in types:
            family = t.split(".")[0]
            assert family.endswith("d") or "d" in family[2:], (
                f"{arch}: {t} has no instance storage; it would boot a runner "
                f"that cannot build /mnt/fcvm-btrfs"
            )


def case_arm_types_are_graviton3_or_newer():
    """Graviton2 cannot run the nested-virtualisation tests.

    fcvm's test_kvm cases need FEAT_NV2, which arrived with Graviton3. On
    2026-08-15 c6gd.metal and m6gd.metal were added to the ARM list for spot
    availability -- both have instance storage, so the storage check passed --
    and the next job to land on a c6gd.metal turned main red with 9 failures
    (nested KVM, NFS, reflink, copy_file_range). Having a local disk is
    necessary, not sufficient.

    The family digit is the generation: c6gd -> 6 (Graviton2),
    c7gd -> 7 (Graviton3), r8gd -> 8 (Graviton4).
    """
    module = webhook(FakeEC2([]))
    for t in module["get_instance_types"]("arm64"):
        family = t.split(".")[0]
        digits = re.findall(r"\d+", family)
        assert digits, f"cannot read a generation out of {t}"
        assert int(digits[0]) >= 7, (
            f"{t} is Graviton{int(digits[0]) - 4} class (family digit "
            f"{digits[0]}); nested virtualisation needs FEAT_NV2, so ARM "
            f"runners must be Graviton3+ (family digit >= 7)"
        )


def case_synchronous_exception_still_falls_through():
    """The original exception path still advances when AWS does raise."""
    ec2 = FakeEC2(run_instances_errors={type_order()[0]: "InsufficientInstanceCapacity"})
    webhook(ec2)["launch_runner"]("x86_64")
    assert launched_types(ec2) == type_order()[:2], launched_types(ec2)


def case_incident_replay_three_dead_c5d_launches():
    """2026-08-07: three c5d.metal launches at 18:41, 18:46 and 18:51.

    All three returned an instance ID, none reached `running`, and AWS did not
    report instance-terminated-no-capacity until 20:31. The old loop saw no
    exception, so every retry picked c5d.metal again and the rest of the list
    was never tried.
    """
    ec2 = FakeEC2([
        instance("i-001e64c56eb71053b", "c5d.metal", "pending", 79),
        instance("i-012093644a97c1b37", "c5d.metal", "pending", 74),
        instance("i-00ead8c13e0bfffff", "c5d.metal", "pending", 69),
    ])
    # GitHub is reachable and has no runner registered for any husk -- required:
    # without a GitHub view, get_capacity deliberately degrades to the instance
    # count and husks WOULD hold slots (fail toward over-counting).
    module = webhook(ec2, github=FakeGitHub())
    module["launch_runner"]("x86_64")
    assert launched_types(ec2) == [type_order()[1]], launched_types(ec2)
    # And the husks are not counted as runners, so the pool is not "full":
    # stalled pending instances are past BOOT_GRACE_MINUTES and not online.
    assert module["get_capacity"]("x86_64")["counted"] == 0


def case_handler_launches_next_type_when_the_pool_is_all_husks():
    """End to end through the webhook entry point, not just launch_runner.

    Four x86 instances exist, so the old count reported the pool full and returned
    "Max x86_64 runners (4) reached". All four are dead launches, so the pool is
    really empty and the next instance type is the one to try.
    """
    ec2 = FakeEC2([
        instance("i-001e64c56eb71053b", "c5d.metal", "pending", 79),
        instance("i-012093644a97c1b37", "c5d.metal", "pending", 74),
        instance("i-00ead8c13e0bfffff", "c5d.metal", "pending", 69),
        instance("i-0fb9768c36e56129d", "c5d.metal", "pending", 60),
    ])
    event = {"body": json.dumps({
        "action": "queued",
        "workflow_job": {"labels": ["self-hosted", "Linux", "X64"]},
    })}
    # GitHub reachable, nothing registered: see the husk-counting note above.
    result = webhook(ec2, github=FakeGitHub())["handler"](event, None)
    assert f"Launched 1 x86_64 runner(s) ({type_order()[1]})" in result["body"], result
    assert launched_types(ec2) == [type_order()[1]], launched_types(ec2)


def case_handler_still_refuses_when_the_pool_is_genuinely_full():
    """The cap must still hold for runners that can actually take a job."""
    ec2 = FakeEC2([instance(f"i-live{n}", "c5d.metal", "running", 20) for n in range(4)])
    event = {"body": json.dumps({
        "action": "queued",
        "workflow_job": {"labels": ["self-hosted", "Linux", "X64"]},
    })}
    result = webhook(ec2)["handler"](event, None)
    assert result["body"] == "Max x86_64 runners (4) reached", result
    assert launched_types(ec2) == [], launched_types(ec2)


def case_ordinary_spot_reclaim_does_not_rotate():
    """A reclaimed runner is not a failed launch.

    Server.SpotInstanceTermination covers a runner that worked for an hour and was
    taken back, so it must not push the working type to the back of the list.
    """
    ec2 = FakeEC2([instance("i-reclaimed", "c7gd.metal", "terminated", 90, arch="arm64",
                            state_reason="Server.SpotInstanceTermination")])
    webhook(ec2)["launch_runner"]("arm64")
    assert launched_types(ec2) == ["c7gd.metal"], launched_types(ec2)


def case_starved_fires_when_wedged_runners_hold_the_cap():
    """The 2026-08-07 shape: the pool is FULL of runners that cannot take work.

    Both wedged ARM runners were GitHub-online for the whole 3.5-hour window, so
    `counted` was 4 of 4 and the original `counted < max_runners` gate held
    ScaleUpStarved at 0 for exactly the incident it was written for. Queued work plus
    a refusal is the signal; whether the cap is full is not.
    """
    emit = webhook(FakeEC2([]))["emit_decision"]
    line = capture_emf(emit, arch="arm64", queued_jobs=3,
                       capacity={"counted": 4, "instances": 4, "online": 4,
                                 "booting": 0, "degraded": False},
                       max_runners=4, decision="blocked", detail="cap reached")
    assert line["ScaleUpStarved"] == 1, line
    assert line["OnlineRunners"] == 4, line
    # Runners exist and answer GitHub; they just cannot drain the queue.
    assert line["ZeroOnlineRunners"] == 0, line


def case_starved_is_quiet_when_nothing_is_queued():
    """A refusal with no queued work is just the cap doing its job."""
    emit = webhook(FakeEC2([]))["emit_decision"]
    line = capture_emf(emit, arch="arm64", queued_jobs=0,
                       capacity={"counted": 4, "instances": 4, "online": 4,
                                 "booting": 0, "degraded": False},
                       max_runners=4, decision="blocked", detail="cap reached")
    assert line["ScaleUpStarved"] == 0, line


def case_zero_online_fires_when_the_pool_is_empty():
    """Queued work, nothing online, and nothing on the way either.

    `booting: 0` is the point. An earlier version of this case used booting: 4, which
    is a cold start rather than an outage -- it asserted the very false positive the
    boot-grace suppression exists to prevent, and only passed because the bug was there.
    """
    emit = webhook(FakeEC2([]))["emit_decision"]
    line = capture_emf(emit, arch="x86_64", queued_jobs=2,
                       capacity={"counted": 0, "instances": 0, "online": 0,
                                 "booting": 0, "degraded": False},
                       max_runners=4, decision="blocked", detail="all husks reaped")
    assert line["ZeroOnlineRunners"] == 1, line
    assert line["OnlineRunners"] == 0, line


def case_zero_online_is_quiet_during_a_cold_start():
    """A normal cold start has online == 0 while metal boots -- that is not an outage.

    BOOT_GRACE_MINUTES allows 15 minutes for registration, so keying on `online` alone
    would raise this on the poll after every cold start and page in ten minutes while
    the capacity that was just requested was arriving exactly as intended.
    """
    emit = webhook(FakeEC2([]))["emit_decision"]
    line = capture_emf(emit, arch="arm64", queued_jobs=2,
                       capacity={"counted": 2, "instances": 2, "online": 0,
                                 "booting": 2, "degraded": False},
                       max_runners=4, decision="launched", detail="cold start")
    assert line["ZeroOnlineRunners"] == 0, line


def case_zero_online_is_suppressed_while_degraded():
    """With GitHub unreachable `online` is 0 by construction -- pure noise."""
    emit = webhook(FakeEC2([]))["emit_decision"]
    line = capture_emf(emit, arch="x86_64", queued_jobs=2,
                       capacity={"counted": 4, "instances": 4, "online": 0,
                                 "booting": 0, "degraded": True},
                       max_runners=4, decision="blocked", detail="github unreachable")
    assert line["ZeroOnlineRunners"] == 0, line


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

def cleanup(ec2, github, lambda_client=None, env=None, ssm=None):
    return load_lambda(CLEANUP_SRC, ec2, ssm or FakeSSM(), lambda_client or FakeLambdaClient(),
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


# --------------------------------------------------------------------------
# Cases: the age policy - drain at the soft cap, hard ceiling above it
# --------------------------------------------------------------------------

# The policy these cases assert, in minutes. Spelled out rather than read back
# from the Lambda, so a case says what the fleet is supposed to do instead of
# following whatever the constants happen to hold;
# case_absolute_runner_lifetime_is_13h30m is what ties the two together.
SOFT_CAP_MINUTES = 12 * 60          # MAX_INSTANCE_AGE_HOURS: stop taking new work
DRAIN_GRACE_MINUTES = 90            # time an in-flight job gets to finish
HARD_CEILING_MINUTES = SOFT_CAP_MINUTES + DRAIN_GRACE_MINUTES   # 13h30m, unconditional


def runner_record(instance_id="i-aged", busy=True, status="online", runner_id=77):
    """One entry as GitHub's /actions/runners list returns it."""
    return {"id": runner_id, "name": f"runner-{instance_id}", "busy": busy, "status": status}


def age_poll(age_minutes, runners=(), runners_error=False, delete_error=False,
             instance_id="i-aged", runs=(), terminate_error=None, recheck=None,
             extra_instances=()):
    """One cleanup poll over a single running runner of the given age.

    Returns (result, ec2, github, stdout). Driving the real handler rather than
    age_policy() alone is deliberate: it is the wiring, not the predicate, that
    decides whether an instance is actually terminated.
    """
    ec2 = FakeEC2([instance(instance_id, "c7g.metal", "running", age_minutes, arch="arm64",
                            tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()})]
                  + list(extra_instances),
                  terminate_error=terminate_error)
    github = FakeGitHub(runs=list(runs), runners=list(runners), recheck=recheck,
                        runners_error=runners_error, delete_error=delete_error)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = cleanup(ec2, github)["handler"]({}, None)
    return result, ec2, github, buf.getvalue()


def terminated_ids(ec2):
    return [i for kw in ec2.ops("terminate_instances") for i in kw["InstanceIds"]]


def still_running(ec2):
    """Instances the poll left running, read off the fake's state.

    Call counts answer "was terminate_instances invoked". This answers "is the
    instance still there", which is the question a case about not killing a
    runner is actually asking.
    """
    return sorted(i["InstanceId"] for i in ec2.instances
                  if i["State"]["Name"] == "running")


def case_busy_runner_past_the_soft_cap_is_drained_not_killed():
    """ejc3/fcvm#884: a job in flight at 12h must be allowed to finish.

    The pre-fix Lambda terminated at MAX_INSTANCE_AGE_HOURS regardless of busy.
    On 2026-08-28/29 that killed i-09fff3a7d97fd4066 at 12.07h and
    i-02fefa9deeb59e9c8 at 12.02h, both mid-job, both reported to GitHub as
    "The self-hosted runner lost communication with the server".
    """
    result, ec2, github, _ = age_poll(SOFT_CAP_MINUTES + 30, runners=[runner_record()])
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["draining"] == ["i-aged"], result
    # And it is NOT deregistered while busy. GitHub documents that DELETE as
    # "forces the removal of a self-hosted runner" and says nothing about a job
    # the runner is part-way through; a forced removal that ends the job is the
    # failure this case exists to prevent. The runner stops taking new work by
    # being terminated on the first poll that sees it idle, which is at most one
    # 5-minute interval after its job ends.
    assert github.deletes == [], github.deletes


def case_busy_runner_just_under_the_hard_ceiling_is_still_draining():
    """The grace is a real window, not a rounding error on the soft cap."""
    result, ec2, _, _ = age_poll(HARD_CEILING_MINUTES - 5, runners=[runner_record()])
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["draining"] == ["i-aged"], result


def case_busy_runner_past_the_hard_ceiling_is_terminated():
    """The ceiling is unconditional. ejc3/fcvm#871's wedged host reports busy forever.

    Draining on `busy` is only safe because this bound exists: a host whose
    scheduler has failed holds its job for as long as it is alive, so waiting for
    "not busy" is waiting for something that never comes.
    """
    result, ec2, github, _ = age_poll(HARD_CEILING_MINUTES + 5, runners=[runner_record()])
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["hard_killed"] == ["i-aged"], result
    assert github.deletes, "the runner must be deregistered as well as terminated"


def case_hard_ceiling_kill_of_a_busy_runner_is_loud():
    """The log line is the only trace that the loss was ours and not AWS's.

    All three causes render identically on GitHub as "lost communication with
    the server", so the Lambda has to say which one it was.
    """
    _, _, _, out = age_poll(HARD_CEILING_MINUTES + 5, runners=[runner_record()])
    assert "HARD-CEILING KILL" in out, out
    assert "not an AWS spot reclaim" in out, out
    assert "busy=True" in out, out


def case_idle_runner_past_the_soft_cap_is_terminated_immediately():
    """Draining is not a reprieve: an idle over-age runner goes now.

    This is what keeps the drain from becoming a way to live longer. It is also
    the only mechanism stopping a drained runner picking up new work, so it must
    fire on the first poll that observes idleness, not at lease expiry.
    """
    result, ec2, github, _ = age_poll(SOFT_CAP_MINUTES + 5,
                                      runners=[runner_record(busy=False)])
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["over_age"] == ["i-aged"], result
    assert result["draining"] == [], result
    assert result["hard_killed"] == [], result
    assert github.deletes, "an idle drained runner must be deregistered"


def case_unreachable_github_drains_inside_the_grace():
    """No answer from GitHub is not evidence that the runner is idle.

    Reading an API failure as "idle" would terminate a runner mid-job on every
    GitHub blip, which is ejc3/fcvm#884 again with a different trigger. The ceiling below
    is what makes it safe to wait instead.
    """
    result, ec2, _, _ = age_poll(SOFT_CAP_MINUTES + 30, runners_error=True)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["draining"] == ["i-aged"], result


def case_unreachable_github_is_still_terminated_at_the_ceiling():
    """The ceiling cannot be deferred by a GitHub error.

    get_runners() turns the exception into an unread roster, so the reaper has
    no record at all for this instance - exactly the state in which a bound that
    needed one would leak the instance forever.
    """
    result, ec2, _, out = age_poll(HARD_CEILING_MINUTES + 5, runners_error=True)
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["over_age"] == ["i-aged"], result
    assert result["hard_killed"] == ["i-aged"], result
    assert "HARD-CEILING KILL" in out, out


def case_runner_missing_from_github_is_still_terminated_at_the_ceiling():
    """GitHub answers and has no record for this instance: same outcome."""
    result, ec2, _, _ = age_poll(HARD_CEILING_MINUTES + 5, runners=[])
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["hard_killed"] == ["i-aged"], result


def case_ceiling_terminates_even_when_deregistration_fails():
    """A failed DELETE must not abort the terminate that follows it."""
    result, ec2, github, _ = age_poll(HARD_CEILING_MINUTES + 5, runners=[runner_record()],
                                      delete_error=True)
    assert github.deletes, "the deregistration must at least be attempted"
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["hard_killed"] == ["i-aged"], result


def case_busy_runner_under_the_soft_cap_is_untouched():
    """Ordinary life is unchanged: renew the lease, terminate nothing."""
    result, ec2, github, _ = age_poll(SOFT_CAP_MINUTES - 60, runners=[runner_record()])
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["draining"] == [], result
    assert result["over_age"] == [], result
    assert result["renewed"] == ["i-aged"], result
    assert github.deletes == [], github.deletes


def case_age_policy_ceiling_ignores_every_reported_runner_state():
    """Past the ceiling the verdict is the same for every possible input.

    The point of the ceiling is that it is computable from the launch time
    alone. Anything it consulted - a busy flag, a status, a tag, a GitHub
    response - is something that can be missing or wrong, and a bound that can be
    deferred by a broken component is not a bound.
    """
    module = cleanup(FakeEC2(), FakeGitHub())
    policy = module["age_policy"]
    launched = NOW - timedelta(minutes=HARD_CEILING_MINUTES + 1)
    states = [
        None, {},
        {"busy": True, "status": "online"},
        {"busy": True, "status": "offline"},
        {"busy": True, "status": None},
        {"busy": False, "status": "online"},
        {"busy": None, "status": None},
        {"status": "online"},
        {"id": 1},
    ]
    for state in states:
        verdict = policy(NOW, launched, state)
        assert verdict == module["TERMINATE_CEILING"], (state, verdict)


def case_malformed_github_timestamp_cannot_block_the_ceiling():
    """A bad value from GitHub must not abort the poll before anything is reaped.

    get_stuck_runners() runs before the age phase. parse_ts() used to hand back a
    NAIVE datetime for a timestamp carrying no timezone designator, and comparing
    that to the aware `now` raises TypeError out of the entire poll: no lease
    renewals, no reaping, and in particular no hard ceiling. That is the ceiling
    being deferred by a GitHub value, which is the one thing it must never be.
    """
    result, ec2, _, _ = age_poll(
        HARD_CEILING_MINUTES + 5, runners=[runner_record()],
        runs=[{"id": 1, "status": "in_progress", "run_started_at": "2026-08-07T16:00:00"}])
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["hard_killed"] == ["i-aged"], result


def case_a_bad_runner_record_cannot_block_the_ceiling():
    """One unusable entry in GitHub's runner list must not kill the poll.

    The orphan phase calls runner_name.startswith() on every key, so a record whose
    name is not a string raises AttributeError out of the whole invocation, and
    every instance - including one past the ceiling - survives it.
    """
    result, ec2, _, _ = age_poll(
        HARD_CEILING_MINUTES + 5,
        runners=[{"id": 1, "name": None, "busy": True, "status": "online"},
                 runner_record()])
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["hard_killed"] == ["i-aged"], result


def case_one_unreadable_instance_cannot_block_another_ceiling_kill():
    """A malformed EC2 record must cost that instance, not the whole sweep.

    The age of an instance with no LaunchTime cannot be computed, so there is no
    safe verdict for it and it is skipped and logged. What must not happen is the
    exception ending the loop, because everything after it - here a runner well
    past the hard ceiling - then outlives the bound.
    """
    broken = instance("i-broken", "c7g.metal", "running", 120, arch="arm64")
    del broken["LaunchTime"]
    aged = instance("i-aged", "c7g.metal", "running", HARD_CEILING_MINUTES + 5, arch="arm64",
                    tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()})
    ec2 = FakeEC2([broken, aged])
    github = FakeGitHub(runners=[runner_record()])
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = cleanup(ec2, github)["handler"]({}, None)
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["hard_killed"] == ["i-aged"], result
    assert "i-broken" in buf.getvalue(), "the skipped instance must be named in the log"


def case_stuck_scan_still_works_on_a_timestamp_with_no_offset():
    """Surviving a bad timestamp is not enough; the scan must still do its job.

    The handler now swallows anything get_stuck_runners() throws, so a naive
    timestamp would no longer kill the poll - it would silently disable the
    MAX_JOB_RUNTIME_MINUTES reaper for that invocation instead, which is the
    fail-open form of the same bug. parse_ts() stamping UTC is what keeps the scan
    working rather than merely surviving.
    """
    stale = (NOW - timedelta(minutes=300)).replace(tzinfo=None).isoformat()
    ec2 = FakeEC2([instance("i-stuck", "c7g.metal", "running", 60, arch="arm64",
                            tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()})])
    github = FakeGitHub(
        runners=[runner_record("i-stuck")],
        runs=[{"id": 5, "status": "in_progress", "run_started_at": stale}],
        jobs={5: [{"name": "Host-Root-arm64", "status": "in_progress",
                   "started_at": stale, "runner_name": "runner-i-stuck",
                   "labels": ["self-hosted", "Linux", "ARM64"]}]},
    )
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, github)["handler"]({}, None)
    assert result["stuck_terminated"] == ["i-stuck"], result
    assert terminated_ids(ec2) == ["i-stuck"], terminated_ids(ec2)


def case_a_failing_stuck_scan_cannot_block_the_ceiling():
    """Whatever get_stuck_runners() does with a payload, the reaping still runs.

    It is the only GitHub-derived phase ahead of the age phase and it parses
    arbitrary API responses, so it is the likeliest thing to throw something
    nobody predicted. Injecting the failure directly covers the shapes a fixture
    cannot enumerate.
    """
    ec2 = FakeEC2([instance("i-aged", "c7g.metal", "running", HARD_CEILING_MINUTES + 5,
                            arch="arm64",
                            tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()})])
    module = cleanup(ec2, FakeGitHub(runners=[runner_record()]))

    def explode(pat, now):
        raise RuntimeError("GitHub returned something unparseable")

    module["get_stuck_runners"] = explode
    with contextlib.redirect_stdout(io.StringIO()):
        result = module["handler"]({}, None)
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["hard_killed"] == ["i-aged"], result


def case_drain_outranks_an_expired_lease():
    """A draining runner is not handed back to the lease phase.

    A runner that drains does not renew, so its lease expires 60 minutes later
    while it is still inside the grace. If the drain fell through instead of
    ending the iteration, the lease phase would terminate it on that evidence -
    which is the original defect wearing a different hat, since "GitHub did not
    answer" is why the runner is draining in the first place.
    """
    ec2 = FakeEC2([instance("i-aged", "c7g.metal", "running", SOFT_CAP_MINUTES + 30,
                            arch="arm64",
                            tags={"LeaseExpires": (NOW - timedelta(minutes=45)).isoformat()})])
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, FakeGitHub(runners_error=True))["handler"]({}, None)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["draining"] == ["i-aged"], result
    assert result["expired"] == [], result


def case_the_ceiling_fires_at_the_ceiling_not_after_it():
    """Exactly 13h30m is over, not under. Pins >= against a silent >.

    A boundary only reached by a test at the boundary; +/-5 minutes on either
    side cannot tell the two comparisons apart.
    """
    module = cleanup(FakeEC2(), FakeGitHub())
    policy, busy = module["age_policy"], {"id": 1, "busy": True, "status": "online"}
    exactly = NOW - timedelta(minutes=HARD_CEILING_MINUTES)
    a_moment_earlier = NOW - timedelta(minutes=HARD_CEILING_MINUTES, microseconds=-1)
    assert policy(NOW, exactly, busy) == module["TERMINATE_CEILING"]
    assert policy(NOW, a_moment_earlier, busy) == module["DRAIN"]
    # And the soft cap keeps its own boundary: exactly 12h is still ordinary life.
    assert policy(NOW, NOW - timedelta(minutes=SOFT_CAP_MINUTES), busy) == module["KEEP"]


def case_a_failed_terminate_is_never_reported_as_a_termination():
    """A terminate that EC2 rejects leaves the instance RUNNING. Say so.

    The per-instance guard around the loop body must not absorb this. An
    invocation that swallows the rejection, returns terminated=[] and logs it as
    an unreadable EC2 *record* is claiming the fleet's only lifetime bound took
    effect when the instance is still up: fail-open, and mislabelled at that.
    """
    result, ec2, _, out = age_poll(
        HARD_CEILING_MINUTES + 5, runners=[runner_record()],
        terminate_error=FakeClientError("UnauthorizedOperation"))
    assert terminated_ids(ec2) == ["i-aged"], "the terminate must at least be attempted"
    assert result["terminated"] == [], result
    assert result["hard_killed"] == [], result
    assert result["terminate_failed"] == ["i-aged"], result
    assert "TERMINATE FAILED" in out, out
    assert "UNREADABLE INSTANCE RECORD" not in out, out


def case_a_record_with_no_instance_id_cannot_stop_the_later_phases():
    """The sweep's guard names "no InstanceId", so that input must be survivable.

    The stuck-job phase rebuilds the instance-id set from the same reservations
    OUTSIDE the per-instance guard. One record without the key raised KeyError there
    and took every later phase with it - the stuck-job reaper, the orphan cleanup,
    the AMI and stalled-launch sweeps and the launcher - on every poll for as long
    as the record existed.
    """
    nameless = instance("i-nameless", "c7g.metal", "running", 120, arch="arm64")
    del nameless["InstanceId"]
    stalled = instance("i-stalled", "c5d.metal", "pending", 30)
    result, ec2, _, _ = age_poll(HARD_CEILING_MINUTES + 5, runners=[runner_record()],
                                 extra_instances=[nameless, stalled])
    assert result["hard_killed"] == ["i-aged"], result
    # The stalled-launch phase runs after the sweep; if the KeyError is back, the
    # poll never gets there.
    assert result["stalled_launches"] == ["i-stalled"], result


def case_an_idle_verdict_is_rechecked_before_the_runner_is_terminated():
    """The busy flag read at the top of the poll is seconds stale by now.

    Between that read and this terminate comes the rest of the poll. GitHub hands
    out jobs the whole time, so terminating a runner past the soft cap on the
    ORIGINAL observation destroys the job it picked up in the gap - and on that path
    the poll reports the benign "GitHub reports it idle", so the HARD-CEILING KILL
    line would not even record the loss.
    """
    result, ec2, _, _ = age_poll(
        SOFT_CAP_MINUTES + 5,
        runners=[runner_record(busy=False)],
        recheck={77: {"id": 77, "name": "runner-i-aged", "busy": True, "status": "online"}})
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["draining"] == ["i-aged"], result


def case_an_unanswerable_recheck_drains_rather_than_terminating():
    """If the re-read fails there is no fresh evidence, so do not act on stale.

    Costs at most the rest of the grace window, which the ceiling bounds.
    """
    result, ec2, _, _ = age_poll(SOFT_CAP_MINUTES + 5,
                                 runners=[runner_record(busy=False)], recheck={77: None})
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["draining"] == ["i-aged"], result


def case_a_confirmed_idle_runner_is_still_terminated_at_the_soft_cap():
    """The re-check must not turn the drain into a way to live forever."""
    result, ec2, github, _ = age_poll(SOFT_CAP_MINUTES + 5,
                                      runners=[runner_record(busy=False)])
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["over_age"] == ["i-aged"], result
    assert github.deletes, "an idle drained runner must be deregistered"


def case_a_ceiling_kill_of_an_idle_runner_is_quiet():
    """Loud means "we may have destroyed work", so it must not cry wolf.

    A runner can reach the ceiling and only then be observed idle: GitHub was
    unreachable for the whole grace window and answers on the last poll. That is a
    clean reap, and printing HARD-CEILING KILL for it would report a job loss that
    did not happen - the inverse of the mislabelling in ejc3/fcvm#884.
    """
    result, ec2, _, out = age_poll(HARD_CEILING_MINUTES + 5,
                                   runners=[runner_record(busy=False)])
    assert terminated_ids(ec2) == ["i-aged"], terminated_ids(ec2)
    assert result["over_age"] == ["i-aged"], result
    assert result["hard_killed"] == [], result
    assert "HARD-CEILING KILL" not in out, out


def case_a_busy_runner_is_not_deregistered_when_ec2_cannot_be_read():
    """The orphan phase must not read "could not ask EC2" as "the instance is gone".

    It deregisters a runner whose instance has disappeared, and GitHub documents
    that DELETE as forcing the removal. One transient DescribeInstances failure
    therefore forced out a runner in the middle of a job, which is exactly the
    class of loss this file is trying to stop.
    """
    # Deliberately NOT in the sweep's running set, so the cross-check there cannot
    # answer for this and get_instance_state's own verdict is what is under test.
    ec2 = FakeEC2([], lookup_error=FakeClientError("RequestLimitExceeded"))
    github = FakeGitHub(runners=[runner_record("i-live")])
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, github)["handler"]({}, None)
    assert github.deletes == [], github.deletes
    assert result["orphans_cleaned"] == [], result
    assert terminated_ids(ec2) == [], terminated_ids(ec2)


def case_a_runner_whose_instance_really_is_gone_is_still_deregistered():
    """The other half: EC2 saying "no such instance" must still clean the orphan.

    A terminated instance drops out of DescribeInstances entirely about an hour
    later and the call then raises InvalidInstanceID.NotFound, so "gone" arrives
    as an exception too. Telling the two apart is the whole point.
    """
    ec2 = FakeEC2([], lookup_error=FakeClientError("InvalidInstanceID.NotFound"))
    github = FakeGitHub(runners=[runner_record("i-vanished")])
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, github)["handler"]({}, None)
    assert result["orphans_cleaned"] == ["runner-i-vanished"], result
    assert github.deletes, "the orphaned registration must be removed"


def case_the_age_sweep_runs_before_the_optional_cleanups():
    """Phase order is a safety property, because a Lambda timeout is not catchable.

    Everything ahead of the sweep can spend the 240-second budget. The orphan scan
    issues one EC2 describe per registered runner and deregisters at a 10-second
    timeout, and the stuck-job scan can spend eleven GitHub calls at five seconds
    each. If either runs long the invocation dies before a single instance has been
    examined, and the hard ceiling simply does not happen that poll - with nothing
    able to catch it and nothing in this account alarming on Lambda errors. So the
    bound goes first and the optional work goes after it.
    """
    journal = []
    ec2 = FakeEC2([instance("i-aged", "c7g.metal", "running", HARD_CEILING_MINUTES + 5,
                            arch="arm64",
                            tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()})],
                  journal=journal)
    github = FakeGitHub(
        runners=[runner_record(), {"id": 99, "name": "runner-i-vanished",
                                   "busy": False, "status": "offline"}],
        runs=[run(1, "in_progress")], journal=journal)
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, github)["handler"]({}, None)
    assert result["hard_killed"] == ["i-aged"], result
    assert result["orphans_cleaned"] == ["runner-i-vanished"], result

    kill = journal.index("ec2:terminate:i-aged")
    orphan_delete = next(i for i, e in enumerate(journal) if e.startswith("github:DELETE:/actions/runners/99"))
    stuck_scan = next(i for i, e in enumerate(journal) if "/actions/runs?status=in_progress" in e)
    assert kill < orphan_delete, journal
    assert kill < stuck_scan, journal


def case_a_runner_record_with_no_id_is_not_acted_on():
    """A record with no id can be neither re-read nor deregistered, so drop it.

    Keeping it lets two things happen. The idle path terminates on a snapshot it
    cannot confirm, because the fresh re-check is skipped when there is no id to
    re-read. And the orphan phase indexes runner_info['id'] directly, so a None
    would be formatted straight into the DELETE URL. Dropping it in get_runners
    makes the instance simply unknown, which drains and dies at the ceiling.
    """
    result, ec2, github, _ = age_poll(
        SOFT_CAP_MINUTES + 5,
        runners=[{"name": "runner-i-aged", "busy": False, "status": "online"}])
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["draining"] == ["i-aged"], result
    assert not any("None" in url for url in github.requests), github.requests


def case_a_rejected_stuck_reap_does_not_kill_the_poll():
    """The stuck-job reap must go through terminate() like every other site.

    It called ec2.terminate_instances directly, outside any guard, so one rejected
    call raised out of the handler and took every later phase with it - including
    the queued-job launcher, which this file calls the last line of defence for
    webhooks GitHub does not redeliver. The reorder widened that: the orphan
    cleanup used to have run by this point and now has not.
    """
    stale = (NOW - timedelta(minutes=300)).isoformat()
    ec2 = FakeEC2([instance("i-stuck", "c7g.metal", "running", 60, arch="arm64",
                            tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()})],
                  terminate_error=FakeClientError("UnauthorizedOperation"))
    github = FakeGitHub(
        runners=[runner_record("i-stuck")],
        runs=[{"id": 5, "status": "in_progress", "run_started_at": stale}],
        jobs={5: [{"name": "Host-Root-arm64", "status": "in_progress", "started_at": stale,
                   "runner_name": "runner-i-stuck",
                   "labels": ["self-hosted", "Linux", "ARM64"]},
                  job("queued", "arm64")]})
    invoker = FakeLambdaClient()
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        result = cleanup(ec2, github, invoker)["handler"]({}, None)
    assert result["stuck_terminated"] == [], result
    assert result["terminate_failed"] == ["i-stuck"], result
    assert "TERMINATE FAILED" in buf.getvalue()
    # The launcher is the LAST phase, so reaching it proves the poll survived.
    # It is also the phase that matters most: GitHub does not redeliver webhooks,
    # so this poll is the only retry a queued job gets.
    assert invoker.arch_invokes() == {"arm64": 1}, invoker.arch_invokes()


def case_a_rejected_ami_builder_terminate_does_not_kill_the_poll():
    """Same class, the other raw call site."""
    ec2 = FakeEC2([instance("i-ami", "c7g.metal", "running", 200,
                            tags={"Name": "ami-builder-temp"})],
                  terminate_error=FakeClientError("UnauthorizedOperation"))
    queued = run(9, "queued")
    github = FakeGitHub(runs=[queued], jobs={queued["id"]: [job("queued", "x86_64")]})
    invoker = FakeLambdaClient()
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, github, invoker)["handler"]({}, None)
    assert result["ami_builder_terminated"] == [], result
    assert invoker.arch_invokes() == {"x86_64": 1}, invoker.arch_invokes()


def case_a_runner_is_deregistered_only_after_ec2_accepts_the_terminate():
    """Deregistering first, then failing to terminate, is the worst outcome.

    It forces a runner out of GitHub - which is how a job in flight dies - and
    leaves the instance alive anyway. The next poll then has no GitHub record for
    it, so it reads as unknown, drains, and is finally hard-killed 85 minutes
    later while being loudly reported as work we may have destroyed. Terminate
    first: if EC2 refuses, the runner keeps working and keeps its registration.
    """
    result, ec2, github, _ = age_poll(
        SOFT_CAP_MINUTES + 5, runners=[runner_record(busy=False)],
        terminate_error=FakeClientError("UnauthorizedOperation"))
    assert result["terminate_failed"] == ["i-aged"], result
    assert github.deletes == [], github.deletes


def case_a_failed_ceiling_terminate_is_not_announced_as_a_dead_job():
    """HARD-CEILING KILL says a job "is now dead". Only say it if it is.

    Logging before attempting the call produced both "is now dead" and "STILL
    RUNNING" for one instance in one poll, and counted it in hard_killed - the
    number documented as work we may have destroyed.
    """
    result, _, github, out = age_poll(
        HARD_CEILING_MINUTES + 5, runners=[runner_record()],
        terminate_error=FakeClientError("UnauthorizedOperation"))
    assert result["hard_killed"] == [], result
    assert "HARD-CEILING KILL" not in out, out
    assert "TERMINATE FAILED" in out, out
    # And the runner keeps its registration. Deregistering first, then failing to
    # terminate, forces a live runner out of GitHub (killing whatever it runs) and
    # leaves the instance up regardless - the worst of both, for no gain.
    assert github.deletes == [], github.deletes


def case_a_running_instance_is_never_deregistered_on_a_notfound_blip():
    """DescribeInstances is eventually consistent; the bulk read is the witness.

    AWS documents InvalidInstanceID.NotFound as transient after RunInstances, so
    it is not by itself proof that an instance is gone. The sweep has already
    listed every running runner instance this poll, so if the id is in that list
    it is demonstrably alive and its registration must be left alone.
    """
    ec2 = FakeEC2([instance("i-live", "c7g.metal", "running", 60, arch="arm64",
                            tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()})],
                  lookup_error=FakeClientError("InvalidInstanceID.NotFound"))
    github = FakeGitHub(runners=[runner_record("i-live")])
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, github)["handler"]({}, None)
    assert result["orphans_cleaned"] == [], result
    assert github.deletes == [], github.deletes


def case_absolute_runner_lifetime_is_13h30m():
    """The one number a reader of this fleet needs, pinned so it cannot drift.

    12h soft cap + 90m grace. The cleanup Lambda polls every 5 minutes, so the
    observed maximum is this plus at most one poll interval.
    """
    module = cleanup(FakeEC2(), FakeGitHub())
    total = module["MAX_INSTANCE_AGE_HOURS"] * 60 + module["DRAIN_GRACE_MINUTES"]
    assert total == HARD_CEILING_MINUTES == 13 * 60 + 30, total


# --------------------------------------------------------------------------
# Cases: the lease phase - what GitHub's answer is allowed to decide
# --------------------------------------------------------------------------

def lease_poll(lease_minutes_ago=45, age_minutes=60, tags=None, runners=(),
               runners_error=False, runners_total=None, ssm=None,
               instance_id="i-lease", runner_payloads=None):
    """One cleanup poll over a single running runner UNDER the soft cap.

    The lease is what is under test, so the instance is deliberately young
    enough that age_policy() answers KEEP and every verdict below comes from
    the lease phase. `lease_minutes_ago` is how long ago the lease expired.
    """
    all_tags = {"LeaseExpires": (NOW - timedelta(minutes=lease_minutes_ago)).isoformat()}
    all_tags.update(tags or {})
    ec2 = FakeEC2([instance(instance_id, "c7g.metal", "running", age_minutes,
                            arch="arm64", tags=all_tags)])
    github = FakeGitHub(runners=list(runners), runners_error=runners_error,
                        runners_total=runners_total, runner_payloads=runner_payloads)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = cleanup(ec2, github, ssm=ssm)["handler"]({}, None)
    return result, ec2, github, buf.getvalue()


def case_a_busy_runner_survives_a_github_outage_past_its_lease():
    """ejc3/aws#45: an unread roster is not evidence that a runner is idle.

    The lease made a single blip survivable and an OUTAGE fatal: once GitHub
    had been unreadable for longer than the remaining lease, every runner took
    the idle path, its lease was allowed to expire, and it was terminated
    mid-job while still under the soft cap. On GitHub that reads as "The
    self-hosted runner lost communication with the server", which is
    indistinguishable from a spot reclaim (ejc3/fcvm#884).
    """
    result, ec2, _, _ = lease_poll(
        lease_minutes_ago=45, runners_error=True,
        tags={"RunnerSeenAt": (NOW - timedelta(minutes=50)).isoformat()})
    assert still_running(ec2) == ["i-lease"], still_running(ec2)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["expired"] == [], result
    assert result["held"] == ["i-lease"], result
    # HELD, not renewed. Renewing on an unread roster would make a wedged host
    # immortal, which is the bound ejc3/fcvm#871 needs; the lease stays where it
    # is and the age ceiling remains the thing that ends this instance.
    lease_writes = [kw for kw in ec2.ops("create_tags")
                    if any(t["Key"] == "LeaseExpires" for t in kw["Tags"])]
    assert lease_writes == [], lease_writes


def case_an_idle_runner_past_its_lease_is_still_terminated():
    """Scale-down itself, which the fix above must not disable.

    GitHub answered and reported busy=false. That is a verdict about this
    runner, so the lease is allowed to lapse and the instance goes.
    """
    result, ec2, _, _ = lease_poll(runners=[runner_record("i-lease", busy=False)])
    assert terminated_ids(ec2) == ["i-lease"], terminated_ids(ec2)
    assert result["expired"] == ["i-lease"], result
    assert result["held"] == [], result


def case_a_runner_that_never_registered_still_dies_at_its_lease():
    """A box that booted and never joined must not be held to the ceiling.

    user_data registers only when the IPv6 gate passes AND the PAT reads back
    from SSM, so an instance that stays `running` and never registers is a
    designed-for outcome, not a hypothetical. Nothing else reaps it: phase 5
    only walks `pending`, and the age phase would leave it running for 13h30m.
    The lease is what kills it, and GitHub listing other runners while never
    having listed this one is a real answer about it.
    """
    result, ec2, _, _ = lease_poll(runners=[runner_record("i-other")])
    assert terminated_ids(ec2) == ["i-lease"], terminated_ids(ec2)
    assert result["expired"] == ["i-lease"], result


def case_a_registered_runner_missing_from_a_readable_roster_holds_its_lease():
    """Seen before, absent now: one of the two explanations is a live job.

    A roster we could read is authoritative about REGISTRATION. It is not
    authoritative about a box that was registered on the previous poll: a real
    deregistration and an answer that dropped records look identical from here.
    Hold the lease and let the ceiling bound it.
    """
    result, ec2, _, _ = lease_poll(
        runners=[runner_record("i-other")],
        tags={"RunnerSeenAt": (NOW - timedelta(minutes=6)).isoformat()})
    assert still_running(ec2) == ["i-lease"], still_running(ec2)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["held"] == ["i-lease"], result


def case_a_truncated_roster_cannot_expire_a_lease():
    """A short page reads exactly like "this runner is not registered".

    GitHub reports total_count beside the page, so a read that came back short
    is detectable rather than silently partial. Detect it and the whole roster
    is unread; miss it and truncation terminates whichever runners fell off the
    end - the fail-open of ejc3/aws#45 arriving through pagination instead of
    through an exception.
    """
    result, ec2, _, _ = lease_poll(runners=[runner_record("i-other")], runners_total=7)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["held"] == ["i-lease"], result


def case_a_missing_pat_is_not_evidence_that_a_runner_is_idle():
    """No PAT means no answer, not "nothing is registered".

    get_github_pat() returns None for a missing or placeholder parameter, and
    the roster was then skipped entirely and treated as empty - so an SSM
    problem, or a rotated-out PAT, reaped the whole fleet an hour later.
    """
    result, ec2, _, _ = lease_poll(ssm=FakeSSM(pat="placeholder"))
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["held"] == ["i-lease"], result


def case_a_record_with_no_busy_flag_is_not_read_as_idle():
    """`.get('busy', False)` read a missing key as "holds no job"."""
    result, ec2, _, _ = lease_poll(
        runners=[{"id": 5, "name": "runner-i-lease", "status": "online"}])
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["held"] == ["i-lease"], result


def case_a_sustained_outage_says_how_long_the_runner_has_been_unobserved():
    """A poll that decides nothing must still say that, and for how long.

    Holding leases silently turns an outage into an absence of log lines, which
    is the same state as a healthy quiet poll. The line carries the duration so
    a blip and a three-hour outage are distinguishable in CloudWatch.
    """
    result, _, _, out = lease_poll(
        runners_error=True,
        tags={"RunnerSeenAt": (NOW - timedelta(hours=3)).isoformat()})
    assert "180m" in out, out
    assert result["held"] == ["i-lease"], result


def case_the_roster_answer_is_recorded_on_the_instance():
    """Two polls: the second has to remember what the first was told.

    The whole distinction between "never joined" and "was here and vanished"
    rests on this tag reaching the instance, so this drives two real polls
    against one EC2 rather than hand-placing the tag and asserting on it.
    """
    inst = instance("i-lease", "c7g.metal", "running", 60, arch="arm64",
                    tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()})
    ec2 = FakeEC2([inst])
    with contextlib.redirect_stdout(io.StringIO()):
        first = cleanup(ec2, FakeGitHub(
            runners=[runner_record("i-lease", busy=False)]))["handler"]({}, None)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    tags = {t["Key"]: t["Value"] for t in inst["Tags"]}
    assert tags.get("RunnerSeenAt") == NOW.isoformat(), tags
    assert first["held"] == [], first

    # The clock is frozen, so the hour that would pass between the two polls is
    # applied to the lease instead: this is the same instance, one lease later.
    tags["LeaseExpires"] = (NOW - timedelta(minutes=45)).isoformat()
    inst["Tags"] = [{"Key": k, "Value": v} for k, v in tags.items()]

    with contextlib.redirect_stdout(io.StringIO()):
        second = cleanup(ec2, FakeGitHub(
            runners=[runner_record("i-other")]))["handler"]({}, None)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert second["held"] == ["i-lease"], second


def case_a_busy_record_with_no_status_holds_its_lease():
    """`busy=true` with no status is absent evidence, not an offline host.

    The offline qualifier exists for the wedged host of ejc3/fcvm#871, which
    reports busy=true and status=offline. A record carrying no status at all is
    a different thing: GitHub said the runner holds a job and said nothing about
    whether it can be reached. Reading that as the wedge terminates a working
    runner on a field GitHub did not send.
    """
    result, ec2, _, _ = lease_poll(
        runners=[{"id": 7, "name": "runner-i-lease", "busy": True}])
    assert still_running(ec2) == ["i-lease"], still_running(ec2)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert result["held"] == ["i-lease"], result


def case_an_explicitly_offline_busy_runner_still_loses_its_lease():
    """The wedge itself is unchanged: busy=true, status=offline, lease lapses."""
    result, ec2, _, _ = lease_poll(
        runners=[runner_record("i-lease", busy=True, status="offline")])
    assert terminated_ids(ec2) == ["i-lease"], terminated_ids(ec2)
    assert result["expired"] == ["i-lease"], result


def case_explicit_renewal_provenance_proves_the_runner_once_registered():
    """Registration is persisted explicitly, never inferred from lease timing."""
    result, ec2, _, _ = lease_poll(
        age_minutes=200, lease_minutes_ago=45, runners=[runner_record("i-other")],
        tags={"LeaseRenewedAt": (NOW - timedelta(minutes=46)).isoformat()})
    assert still_running(ec2) == ["i-lease"], still_running(ec2)
    assert result["held"] == ["i-lease"], result


def case_lease_timestamp_microseconds_are_not_registration_provenance():
    """An initial lease can straddle EC2's launch-time precision by one microsecond.

    None of the three values below says GitHub ever listed the instance. Inferring
    registration from `LeaseExpires > LaunchTime + 60m` turns only the +1us value
    into a registered runner and holds that unregistered husk to the hard ceiling.
    """
    age = timedelta(minutes=200)
    launch = NOW - age
    for offset in (-1, 0, 1):
        expiry = launch + timedelta(minutes=60, microseconds=offset)
        ec2 = FakeEC2([instance(f"i-husk-{offset}", "c7g.metal", "running", 200,
                                arch="arm64", tags={"LeaseExpires": expiry.isoformat()})])
        with contextlib.redirect_stdout(io.StringIO()):
            result = cleanup(ec2, FakeGitHub(
                runners=[runner_record("i-other")]))["handler"]({}, None)
        assert terminated_ids(ec2) == [f"i-husk-{offset}"], (offset, terminated_ids(ec2))
        assert result["expired"] == [f"i-husk-{offset}"], (offset, result)


def case_an_initial_lease_does_not_turn_a_legacy_husk_into_a_registered_runner():
    """Setting a missing initial lease must not persist renewal provenance.

    A legacy running instance with neither a lease nor a GitHub registration gets
    one grace lease. The next answered poll must still reap it; using renew_lease
    for the initial write makes the new deadline look like evidence of a job.
    """
    inst = instance("i-husk", "c7g.metal", "running", 200, arch="arm64")
    ec2 = FakeEC2([inst])
    github = FakeGitHub(runners=[runner_record("i-other")])
    with contextlib.redirect_stdout(io.StringIO()):
        first = cleanup(ec2, github)["handler"]({}, None)
    assert terminated_ids(ec2) == [], terminated_ids(ec2)
    assert first["renewed"] == [], first
    tags = {t["Key"]: t["Value"] for t in inst["Tags"]}
    assert "LeaseRenewedAt" not in tags, tags

    tags["LeaseExpires"] = (NOW - timedelta(microseconds=1)).isoformat()
    inst["Tags"] = [{"Key": key, "Value": value} for key, value in tags.items()]
    with contextlib.redirect_stdout(io.StringIO()):
        second = cleanup(ec2, github)["handler"]({}, None)
    assert terminated_ids(ec2) == ["i-husk"], terminated_ids(ec2)
    assert second["expired"] == ["i-husk"], second


def case_busy_renewal_persists_explicit_provenance_with_the_lease():
    """The successful renewal write itself must leave durable provenance."""
    result, ec2, _, _ = lease_poll(
        lease_minutes_ago=-5, runners=[runner_record("i-lease", busy=True)])
    assert result["renewed"] == ["i-lease"], result
    lease_writes = [kw for kw in ec2.ops("create_tags")
                    if any(tag["Key"] == "LeaseExpires" for tag in kw["Tags"])]
    assert len(lease_writes) == 1, lease_writes
    written = {tag["Key"]: tag["Value"] for tag in lease_writes[0]["Tags"]}
    assert written["LeaseRenewedAt"] == NOW.isoformat(), written


def case_unusable_runner_identity_makes_the_roster_unread():
    """Names must contain text and ids must be positive, non-bool integers."""
    invalid = [
        {"id": 7, "name": ""},
        {"id": 7, "name": "   "},
        {"id": True, "name": "runner-i-lease"},
        {"id": False, "name": "runner-i-lease"},
        {"id": 0, "name": "runner-i-lease"},
        {"id": -1, "name": "runner-i-lease"},
        {"id": 7.0, "name": "runner-i-lease"},
        {"id": "7", "name": "runner-i-lease"},
    ]
    for identity in invalid:
        record = {**identity, "busy": False, "status": "online"}
        result, ec2, github, _ = lease_poll(runners=[record])
        assert still_running(ec2) == ["i-lease"], (identity, still_running(ec2))
        assert result["held"] == ["i-lease"], (identity, result)
        assert github.deletes == [], (identity, github.deletes)


def case_a_roster_that_changes_between_reads_cannot_prove_absence():
    """A concurrent registration makes a one-pass absence destructive and stale."""
    other = runner_record("i-other", runner_id=1)
    target = runner_record("i-lease", runner_id=2)
    payloads = [
        {"total_count": 1, "runners": [other]},
        {"total_count": 2, "runners": [other, target]},
    ]
    result, ec2, _, _ = lease_poll(
        runners=[other, target], runner_payloads=payloads)
    assert still_running(ec2) == ["i-lease"], still_running(ec2)
    assert result["held"] == ["i-lease"], result


def case_a_duplicate_across_pages_cannot_prove_absence():
    """Pagination churn can repeat a name or id and silently skip another."""
    first = [runner_record(f"i-other-{number}", runner_id=number + 1)
             for number in range(100)]
    repeats = [
        first[-1],
        {**first[-1], "name": "runner-i-different-name"},
        {**first[-1], "id": 1001},
    ]
    for repeated in repeats:
        github = FakeGitHub(
            runners=first,
            runner_payloads=[
                {"total_count": 101, "runners": first},
                {"total_count": 101, "runners": [repeated]},
            ])
        inst = instance("i-lease", "c7g.metal", "running", 60, arch="arm64",
                        tags={"LeaseExpires": (NOW - timedelta(minutes=45)).isoformat()})
        ec2 = FakeEC2([inst])
        with contextlib.redirect_stdout(io.StringIO()):
            result = cleanup(ec2, github)["handler"]({}, None)
        assert still_running(ec2) == ["i-lease"], (repeated, still_running(ec2))
        assert result["held"] == ["i-lease"], (repeated, result)


def case_a_listed_runner_with_no_id_holds_its_lease():
    """A record we cannot act on is still a record that GitHub listed.

    An id-less record is dropped from the actionable roster, because every
    action on a runner needs the id. Dropping it from the ANSWER as well made
    the instance read as never-registered, which lets its lease lapse and
    terminates it - a live runner killed over a missing field.
    """
    result, ec2, github, _ = lease_poll(
        runners=[{"name": "runner-i-lease", "busy": True, "status": "online"}])
    assert still_running(ec2) == ["i-lease"], still_running(ec2)
    assert result["held"] == ["i-lease"], result
    assert not any("None" in url for url in github.requests), github.requests


def case_a_runner_record_with_no_name_makes_the_roster_unread():
    """A nameless record cannot be discarded into evidence of absence."""
    result, ec2, _, _ = lease_poll(
        runners=[{"id": 7, "busy": True, "status": "online"}])
    assert still_running(ec2) == ["i-lease"], still_running(ec2)
    assert result["held"] == ["i-lease"], result


def case_a_roster_of_exactly_the_page_limit_is_still_a_complete_read():
    """Ten full pages that add up to GitHub's own total_count are not truncated.

    Page-limit and short-page are two different ways to finish, and only the
    first was treated as a failure. A roster that ends exactly on the limit is
    complete if the count matches, and calling it unread holds every lease in
    the fleet on a read that was fine.
    """
    roster = [{"id": n, "name": f"runner-i-other{n}", "busy": False, "status": "online"}
              for n in range(1, 1001)]
    result, ec2, _, _ = lease_poll(runners=roster)
    assert terminated_ids(ec2) == ["i-lease"], terminated_ids(ec2)
    assert result["expired"] == ["i-lease"], result


def case_the_webhook_accepts_a_complete_roster_at_the_page_limit():
    """The launch-side reader uses the same count proof at its page limit."""
    roster = [{"id": n, "name": f"runner-i-live{n}", "busy": False,
               "status": "online"} for n in range(1, 1001)]
    github = FakeGitHub(runners=roster)
    names = webhook(FakeEC2(), github=github)["get_online_runner_names"]()
    assert names == {r["name"] for r in roster}, names
    roster_reads = [url for url in github.requests if "/actions/runners?" in url]
    assert len(roster_reads) == 10, roster_reads


def case_every_ceiling_terminate_precedes_every_optional_tag_write():
    """No fleet member may pay for a write before every ceiling is applied.

    A younger instance is deliberately listed first and needs both the seen tag
    and a lease renewal. Either write can consume the Lambda's remaining budget;
    the older instance later in the response must already have been terminated.
    """
    journal = []
    ec2 = FakeEC2([
        instance("i-young", "c7g.metal", "running", 60, arch="arm64",
                 tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()}),
        instance("i-aged", "c7g.metal", "running", HARD_CEILING_MINUTES + 5,
                 arch="arm64",
                 tags={"LeaseExpires": (NOW + timedelta(minutes=30)).isoformat()}),
    ],
                  journal=journal)
    github = FakeGitHub(runners=[runner_record("i-young", runner_id=1),
                                 runner_record("i-aged", runner_id=2)], journal=journal)
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, github)["handler"]({}, None)
    assert result["hard_killed"] == ["i-aged"], result
    kill = journal.index("ec2:terminate:i-aged")
    tag_writes = [index for index, event in enumerate(journal)
                  if event.startswith("ec2:create_tags:")]
    assert tag_writes, journal
    assert all(index > kill for index in tag_writes), journal


def case_a_held_lease_does_not_shield_the_instance_beside_it():
    """The verdict is per instance, and one poll can hold one and reap another.

    This is the mixed answer the RunnerSeenAt tag exists for: a roster that
    lists neither box, one of which was registered a moment ago and one of
    which never registered at all. Holding both would leave a husk running to
    the 13h30m ceiling; reaping both is ejc3/aws#45.
    """
    expired = (NOW - timedelta(minutes=45)).isoformat()
    ec2 = FakeEC2([
        instance("i-live", "c7g.metal", "running", 60, arch="arm64",
                 tags={"LeaseExpires": expired,
                       "RunnerSeenAt": (NOW - timedelta(minutes=6)).isoformat()}),
        instance("i-husk", "c7g.metal", "running", 60, arch="arm64",
                 tags={"LeaseExpires": expired}),
    ])
    with contextlib.redirect_stdout(io.StringIO()):
        result = cleanup(ec2, FakeGitHub(runners=[runner_record("i-other")]))["handler"]({}, None)
    assert still_running(ec2) == ["i-live"], still_running(ec2)
    assert terminated_ids(ec2) == ["i-husk"], terminated_ids(ec2)
    assert result["held"] == ["i-live"], result
    assert result["expired"] == ["i-husk"], result


def case_a_held_runner_is_still_terminated_at_the_ceiling():
    """Holding a lease must not become a way to outlive the ceiling.

    The lease phase never sees an instance this old - the age policy answers
    first and its ceiling is derived from launch_time alone - but that ordering
    is the only thing making a held lease safe, so it is pinned here as well as
    at the age policy.
    """
    result, ec2, _, out = lease_poll(age_minutes=HARD_CEILING_MINUTES + 5,
                                     runners_error=True)
    assert terminated_ids(ec2) == ["i-lease"], terminated_ids(ec2)
    assert result["hard_killed"] == ["i-lease"], result
    assert result["held"] == [], result
    assert "HARD-CEILING KILL" in out, out


def case_a_truncated_runner_list_degrades_to_the_instance_count():
    """The webhook Lambda, same defect class: a short page is not four dead runners.

    get_online_runner_names() read one page and treated it as the whole roster,
    so online runners past the page boundary counted as absent, `counted` fell
    below the cap and the launcher added metal to a pool that was already full.
    Unknown health already has a defined answer here - degrade to the instance
    count - and a truncated read is unknown health.
    """
    ec2 = FakeEC2([instance(f"i-live{n}", "c5d.metal", "running", 60) for n in range(4)])
    roster = [{"id": n, "name": f"runner-i-live{n}", "status": "online", "busy": True}
              for n in range(4)]
    github = FakeGitHub(runners=roster[:1], runners_total=4)
    event = {"body": json.dumps({
        "action": "queued",
        "workflow_job": {"labels": ["self-hosted", "Linux", "X64"]},
    })}
    result = webhook(ec2, github=github)["handler"](event, None)
    assert launched_types(ec2) == [], launched_types(ec2)
    assert result["body"] == "Max x86_64 runners (4) reached", result


def case_a_nameless_runner_record_cannot_stop_a_launch():
    """One malformed record must not take scale-up down with it.

    The set comprehension that reads r['name'] sits outside the try in
    get_online_runner_names, so a record without a name raised KeyError out of
    get_capacity and out of the handler. GitHub delivers a workflow_job event
    once and never redelivers it, so the queued job waits for the next poll.
    """
    ec2 = FakeEC2([instance("i-live", "c5d.metal", "running", 60)])
    github = FakeGitHub(runners=[{"id": 1, "status": "online", "busy": False}])
    event = {"body": json.dumps({
        "action": "queued",
        "workflow_job": {"labels": ["self-hosted", "Linux", "X64"]},
    })}
    result = webhook(ec2, github=github)["handler"](event, None)
    assert len(launched_types(ec2)) == 1, launched_types(ec2)
    assert result["body"].startswith("Launched 1 x86_64 runner"), result


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
    """Seven queued arm64 jobs must fill the pool in one poll, not one per poll.

    And the whole deficit must travel in a SINGLE invocation per architecture:
    a burst of single-launch invocations, even serialized by reserved
    concurrency 1, can each miss the instance the previous one just launched
    (DescribeInstances is eventually consistent) and overshoot MAX_RUNNERS.
    """
    busy = run(7, "queued")
    github = FakeGitHub(runs=[busy], jobs={busy["id"]: [job("queued", "arm64") for _ in range(7)]})
    invoker = FakeLambdaClient()
    cleanup(FakeEC2(), github, invoker)["handler"]({}, None)
    assert invoker.arch_invokes() == {"arm64": 4}, invoker.arch_invokes()
    assert invoker.invocations_per_arch() == {"arm64": 1}, invoker.invocations_per_arch()


def case_stale_describe_cannot_overshoot_the_cap():
    """The launch budget is bounded in-process, immune to describe lag.

    FakeEC2 never adds launched instances to its describe results -- the
    worst-case eventual-consistency window, forever. A launch_count of 7
    against an empty pool of max 4 must launch exactly 4, because the
    handler's own loop is the counter, not a re-read of EC2 state.
    """
    ec2 = FakeEC2([])
    event = {"body": json.dumps({
        "action": "queued",
        "workflow_job": {"labels": ["self-hosted", "Linux", "ARM64"]},
        "launch_count": 7,
    })}
    result = webhook(ec2)["handler"](event, None)
    assert "Launched 4 arm64 runner(s)" in result["body"], result
    assert len(launched_types(ec2)) == 4, launched_types(ec2)


def case_github_style_header_casing_verifies():
    """GitHub sends X-Hub-Signature-256; payload format 1.0 preserves that case.

    The lowercase-only lookup 401'd every real delivery regardless of secret --
    the actual root cause of the dead webhook path. The handler must verify
    with the header exactly as GitHub capitalizes it.
    """
    import hmac as hmac_mod
    import hashlib
    secret = "testsecret"
    body = json.dumps({
        "action": "queued",
        "workflow_job": {"labels": ["self-hosted", "Linux", "ARM64"]},
    })
    sig = "sha256=" + hmac_mod.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    event = {"body": body, "requestContext": {}, "headers": {"X-Hub-Signature-256": sig}}
    ec2 = FakeEC2([])
    result = webhook(ec2, github=FakeGitHub(), env={"WEBHOOK_SECRET": secret})["handler"](event, None)
    assert "Launched 1 arm64 runner(s)" in result["body"], result


def case_public_webhook_cannot_amplify_launch_count():
    """launch_count is honored only on IAM-authed direct invokes.

    A real GitHub delivery arrives through API Gateway (requestContext
    present). Even correctly signed, its launch_count must be ignored --
    otherwise anyone with the webhook secret could 4x every launch.
    """
    import hmac as hmac_mod
    import hashlib
    secret = "testsecret"
    body = json.dumps({
        "action": "queued",
        "workflow_job": {"labels": ["self-hosted", "Linux", "ARM64"]},
        "launch_count": 4,
    })
    sig = "sha256=" + hmac_mod.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    event = {"body": body, "requestContext": {}, "headers": {"x-hub-signature-256": sig}}
    ec2 = FakeEC2([])
    result = webhook(ec2, env={"WEBHOOK_SECRET": secret})["handler"](event, None)
    assert "Launched 1 arm64 runner(s)" in result["body"], result
    assert len(launched_types(ec2)) == 1, launched_types(ec2)


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
