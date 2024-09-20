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

from casbin.model.policy_op import PolicyOp
from casbin.persist import batch_adapter, update_adapter
from casbin.synced_enforcer import SyncedEnforcer


class DistributedEnforcer(SyncedEnforcer):
    """DistributedEnforcer wraps SyncedEnforcer for dispatcher."""

    def __init__(self, model=None, adapter=None):
        SyncedEnforcer.__init__(self, model, adapter)

    @classmethod
    async def create(cls, model=None, adapter=None):
        """A factory method that creates and initializes on instances with load_policy() asynchronously"""
        # create an instance using the constructor
        self = DistributedEnforcer(model, adapter)
        # Do not initialize the full policy when using a filtered adapter
        if self._e.adapter and not self._e.is_filtered():
            await self._e.load_policy()
        return self

    async def add_policy_self(self, should_persist, sec, ptype, rules):
        """
        AddPolicySelf provides a method for dispatcher to add authorization rules to the current policy.
        The function returns the rules affected and error.
        """

        no_exists_policy = []
        for rule in rules:
            if not self.get_model().has_policy(sec, ptype, rule):
                no_exists_policy.append(rule)

        if should_persist:
            try:
                if isinstance(self.adapter, batch_adapter):
                    await self.adapter.add_policies(sec, ptype, rules)
            except Exception as e:
                self._e.logger.error("An error occurred: " + e)

        self.get_model().add_policies(sec, ptype, no_exists_policy)

        if sec == "g":
            try:
                self.build_incremental_role_links(PolicyOp.Policy_add, ptype, no_exists_policy)
            except Exception as e:
                self._e.logger.error("An exception occurred: " + e)
                return no_exists_policy

        return no_exists_policy

    async def remove_policy_self(self, should_persist, sec, ptype, rules):
        """
        remove_policy_self provides a method for dispatcher to remove policies from current policy.
        The function returns the rules affected and error.
        """
        if should_persist:
            try:
                if isinstance(self.adapter, batch_adapter):
                    await self.adapter.remove_policy(sec, ptype, rules)
            except Exception as e:
                self._e.logger.error("An exception occurred: " + e)

        effected = self.get_model().remove_policies_with_effected(sec, ptype, rules)

        if sec == "g":
            try:
                self.build_incremental_role_links(PolicyOp.Policy_remove, ptype, rules)
            except Exception as e:
                self._e.logger.error("An exception occurred: " + e)
                return effected

        return effected

    async def remove_filtered_policy_self(self, should_persist, sec, ptype, field_index, *field_values):
        """
        remove_filtered_policy_self provides a method for dispatcher to remove an authorization
        rule from the current policy,field filters can be specified.
        The function returns the rules affected and error.
        """
        if should_persist:
            try:
                await self.adapter.remove_filtered_policy(sec, ptype, field_index, field_values)
            except Exception as e:
                self._e.logger.error("An exception occurred: " + e)

        effects = self.get_model().remove_filtered_policy_returns_effects(sec, ptype, field_index, *field_values)

        if sec == "g":
            try:
                self.build_incremental_role_links(PolicyOp.Policy_remove, ptype, effects)
            except Exception as e:
                self._e.logger.error("An exception occurred: " + e)
                return effects

        return effects

    async def clear_policy_self(self, should_persist):
        """
        clear_policy_self provides a method for dispatcher to clear all rules from the current policy.
        """
        if should_persist:
            try:
                await self.adapter.save_policy(None)
            except Exception as e:
                self._e.logger.error("An exception occurred: " + e)

        self.get_model().clear_policy()

    async def update_policy_self(self, should_persist, sec, ptype, old_rule, new_rule):
        """
        update_policy_self provides a method for dispatcher to update an authorization rule from the current policy.
        """
        if should_persist:
            try:
                if isinstance(self.adapter, update_adapter):
                    await self.adapter.update_policy(sec, ptype, old_rule, new_rule)
            except Exception as e:
                self._e.logger.error("An exception occurred: " + e)
                return False

        rule_updated = self.get_model().update_policy(sec, ptype, old_rule, new_rule)

        if not rule_updated:
            return False

        if sec == "g":
            try:
                self.build_incremental_role_links(PolicyOp.Policy_remove, ptype, [old_rule])
            except Exception:
                return False

            try:
                self.build_incremental_role_links(PolicyOp.Policy_add, ptype, [new_rule])
            except Exception:
                return False

        return True
