import casbin
import datetime
import logging
import sys
from tests.test_enforcer import get_examples, TestCaseBase

log = logging.getLogger(__name__)
loglevel = logging.WARNING
logging.basicConfig(level=loglevel)


def get_function_name():
    return sys._getframe(2).f_code.co_name


def print_time_diff(start, end, time):
    ms = (end - start).total_seconds() * 1000 / time
    log.warning("%s %f ms" % (get_function_name(), ms))


class TestModelBenchmark(TestCaseBase):
    async def test_benchmark_basic_model(self):
        e = await self.get_enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))

        time = 10000
        start = datetime.datetime.now()
        for i in range(0, time):
            e.enforce("alice", "data1", "read")
        end = datetime.datetime.now()
        print_time_diff(start, end, time)

    async def test_benchmark_rbac_model(self):
        e = await self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

        time = 10000
        start = datetime.datetime.now()
        for i in range(0, time):
            e.enforce("alice", "data2", "read")
        end = datetime.datetime.now()
        print_time_diff(start, end, time)


class TestModelBenchmarkSynced(TestModelBenchmark):
    async def get_enforcer(self, model=None, adapter=None):
        # create an instance of class, use await with the factory method
        return await casbin.SyncedEnforcer.create(
            model,
            adapter,
        )
