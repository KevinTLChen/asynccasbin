# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import random

import casbin


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../../examples/"
    return os.path.abspath(examples_path + path)


async def get_enforcer(model=None, adapter=None):
    # create an instance of class, use await with the factory method
    return casbin.Enforcer.create(
        model,
        adapter,
    )


async def _benchmark_has_policy(benchmark, user_num):
    e = await get_enforcer(get_examples("basic_model.conf"))

    await e.add_policies({(f"user{i}", f"data{i // 10}" "read") for i in range(user_num)})

    @benchmark
    def run_benchmark():
        e.has_policy(f"user{random.randint(0, user_num)}", f"data{random.randint(0, user_num) // 10}", "read")


async def test_benchmark_has_policy_small(benchmark):
    await _benchmark_has_policy(benchmark, 100)


async def test_benchmark_has_policy_medium(benchmark):
    await _benchmark_has_policy(benchmark, 1000)


async def test_benchmark_has_policy_large(benchmark):
    await _benchmark_has_policy(benchmark, 10000)


async def _benchmark_add_policy(benchmark, user_num):
    e = await get_enforcer(get_examples("basic_model.conf"))

    await e.add_policies({(f"user{i}", f"data{i // 10}" "read") for i in range(user_num)})

    @benchmark
    async def run_benchmark():
        await e.add_policy(
            f"user{random.randint(0, user_num) + user_num}",
            f"data{(random.randint(0, user_num) + user_num) // 10}",
            "read",
        )


async def test_benchmark_add_policy_small(benchmark):
    await _benchmark_add_policy(benchmark, 100)


async def test_benchmark_add_policy_medium(benchmark):
    await _benchmark_add_policy(benchmark, 1000)


async def test_benchmark_add_policy_large(benchmark):
    await _benchmark_add_policy(benchmark, 10000)


async def _benchmark_remove_policy(benchmark, user_num):
    e = await get_enforcer(get_examples("basic_model.conf"))

    await e.add_policies({(f"user{i}", f"data{i // 10}" "read") for i in range(user_num)})

    @benchmark
    async def run_benchmark():
        await e.remove_policy(f"user{random.randint(0, user_num)}", f"data{random.randint(0, user_num) // 10}", "read")


async def test_benchmark_remove_policy_small(benchmark):
    await _benchmark_remove_policy(benchmark, 100)


async def test_benchmark_remove_policy_medium(benchmark):
    await _benchmark_remove_policy(benchmark, 1000)


async def test_benchmark_remove_policy_large(benchmark):
    await _benchmark_remove_policy(benchmark, 10000)
