import logging
from typing import Sequence

from casbin.enforcer import Enforcer
from casbin.model import Model, FastModel, fast_policy_filter, FunctionMap
from casbin.persist.adapters import FileAdapter
from casbin.util.log import configure_logging


class FastEnforcer(Enforcer):
    _cache_key_order: Sequence[int] = None

    def __init__(self, model=None, adapter=None, enable_log=False, cache_key_order: Sequence[int] = None):
        self._cache_key_order = cache_key_order
        super().__init__(model, adapter, enable_log)

    @classmethod
    async def create(cls, model=None, adapter=None, enable_log=False, cache_key_order: Sequence[int] = None):
        """A factory method that creates and initializes on instances with load_policy() asynchronously"""
        # create an instance using the constructor
        self = FastEnforcer(model, adapter, enable_log, cache_key_order)
        # Do not initialize the full policy when using a filtered adapter
        if self.adapter and not self.is_filtered():
            await self.load_policy()
        return self

    def new_model(self, path="", text=""):
        """creates a model."""
        if self._cache_key_order is None:
            m = Model()
        else:
            m = FastModel(self._cache_key_order)
        if len(path) > 0:
            m.load_model(path)
        else:
            m.load_model_from_text(text)

        return m

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """
        if self._cache_key_order is None:
            result, _ = self.enforce_ex(*rvals)
        else:
            keys = [rvals[x] for x in self._cache_key_order]
            with fast_policy_filter(self.model.model["p"]["p"].policy, *keys):
                result, _ = self.enforce_ex(*rvals)

        return result
