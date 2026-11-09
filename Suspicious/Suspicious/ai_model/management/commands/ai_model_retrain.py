"""ai_model_retrain: start a retrain on the inference server (Plan E, Task 8b), or show, cancel or
wait for one. The result is a `candidate` version; nothing here activates it. Prints job ids,
states, counts and error class names only: never a URL, a token or mail text."""
import time

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Count

from ai_model import ledger, retrain
from ai_model.models import ModelVersion, RetrainJob

J = RetrainJob.State


def describe(job) -> str:
    left_out = f", left out {job.excluded_rows}" if job.excluded_rows else ""
    line = f"job {job.job_id} version {job.target_version}: {job.state} (rows {job.rows}{left_out})"
    if job.error:
        line += f" error {job.error}"
    if job.version_id is not None:
        line += f" eligible: {'yes' if job.version.manifest.get('eligible') else 'no'}"
    return line


class Command(BaseCommand):
    help = "Start a retrain (a candidate model version), or --status, --cancel, --wait."

    def add_arguments(self, parser):
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument("--status", action="store_true", help="counts and the latest jobs")
        mode.add_argument("--cancel", action="store_true", help="cancel the running job")
        parser.add_argument("--wait", action="store_true", help="start, then poll until the job ends")
        parser.add_argument("--timeout", type=int, default=int(retrain.MAX_AGE.total_seconds()),
                            help="seconds --wait polls before giving up (the job keeps running)")

    def handle(self, *args, **opts):
        if not ledger.enabled():
            raise CommandError("the ai_model connector is disabled")
        if opts["status"]:
            return self.status()
        if opts["cancel"]:
            job = retrain.cancel_retrain()
            self.stdout.write(f"cancel requested for job {job.job_id}" if job else "no retrain job is running")
            return
        try:
            job = retrain.start_retrain()
        except retrain.RetrainRefused as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write("started " + describe(job))
        if opts["wait"]:
            self.wait(job, opts["timeout"])

    def wait(self, job, timeout):
        started = time.monotonic()
        while retrain.poll_once(job.job_id) == J.RUNNING:
            if time.monotonic() - started >= timeout:
                raise CommandError(f"job {job.job_id} still running after {timeout} s; see --status")
            time.sleep(retrain.POLL_SECONDS)
        job.refresh_from_db()
        self.stdout.write(describe(job))

    def status(self):
        running = retrain.running_job()
        if running is not None:
            retrain.poll_once(running.job_id)  # settles a job whose poll task was lost
        for model, field in ((RetrainJob, "state"), (ModelVersion, "status")):
            counts = dict(model.objects.values_list(field).annotate(n=Count("pk")))
            self.stdout.write(f"{model.__name__}: " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
        for job in RetrainJob.objects.select_related("version").order_by("-started_at")[:5]:
            self.stdout.write(describe(job))
