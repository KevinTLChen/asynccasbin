# Copyright 2023 The casbin Authors. All Rights Reserved.
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
import time
from typing import Sequence
from unittest import IsolatedAsyncioTestCase

import casbin
from casbin import FastPolicy


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


class TestCaseBase(IsolatedAsyncioTestCase):
    async def get_enforcer(self, model=None, adapter=None, cache_key_order: Sequence[int] = None):
        # create ans instance of the class, use await with the factory method
        return await casbin.FastEnforcer.create(
            model,
            adapter,
            cache_key_order=cache_key_order,
        )


class TestFastEnforcer(TestCaseBase):
    async def test_performance(self) -> None:
        e1 = await self.get_enforcer(
            get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
            get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
        )
        e2 = await self.get_enforcer(
            get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
            get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
            [2, 1],
        )
        s_e1 = time.perf_counter()
        e1.enforce("alice", "data1", "read")
        t_e1 = time.perf_counter() - s_e1
        s_e2 = time.perf_counter()
        e2.enforce("alice", "data1", "read")
        t_e2 = time.perf_counter() - s_e2
        assert t_e1 > t_e2 * 5

    async def test_creates_proper_policy(self) -> None:
        e = await self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            [2, 1],
        )
        self.assertIsInstance(e.model.model["p"]["p"].policy, FastPolicy)

    async def test_initializes_model(self) -> None:
        e = await self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            [2, 1],
        )
        self.assertEqual(
            list(e.model.model["p"]["p"].policy),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
            ],
        )

    async def test_able_to_clear_policy(self) -> None:
        e = await self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            [2, 1],
        )

        e.clear_policy()

        self.assertIsInstance(e.model.model["p"]["p"].policy, FastPolicy)
        self.assertEqual(list(e.model.model["p"]["p"].policy), [])

    async def test_able_to_enforce_rule(self) -> None:
        e = await self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
            [2, 1],
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice2", "data1", "read"))
