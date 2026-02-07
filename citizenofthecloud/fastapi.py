"""
FastAPI middleware for Cloud Identity verification.

Example:
    from citizenofthecloud.fastapi import cloud_guard, CloudGuard

    # As a dependency
    @app.post("/api/task")
    async def task(agent=Depends(cloud_guard())):
        print(f"Request from {agent['name']}")

    # As middleware for all routes
    app.add_middleware(CloudGuard)
"""

from functools import wraps
from typing import Optional

from citizenofthecloud import verify_agent, TrustPolicy

try:
    from fastapi import Request, HTTPException, Depends
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware
except ImportError:
    raise ImportError(
        "FastAPI is required for this module. Install with: "
        "pip install fastapi"
    )


def cloud_guard(policy: Optional[TrustPolicy] = None, **kwargs):
    """
    FastAPI dependency that verifies Cloud Identity headers.

    On success, returns the verified agent dict.
    On failure, raises 401.

    Example:
        @app.post("/api/task")
        async def task(agent=Depends(cloud_guard())):
            print(f"Verified: {agent['name']}")

        @app.post("/api/sensitive")
        async def sensitive(agent=Depends(cloud_guard(
            minimum_trust_score=0.7,
            allowed_autonomy_levels=["agent"],
        ))):
            print(f"High-trust request from {agent['name']}")
    """
    if policy is None and kwargs:
        policy = TrustPolicy(**kwargs)

    async def dependency(request: Request):
        headers = dict(request.headers)
        result = verify_agent(headers, policy=policy)

        if result["verified"]:
            return result["agent"]
        else:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "Cloud Identity verification failed",
                    "reason": result.get("reason"),
                },
            )

    return dependency


def cloud_guard_decorator(policy: Optional[TrustPolicy] = None, **kwargs):
    """
    Decorator version of cloud_guard for use with any async handler.

    Example:
        @app.post("/api/task")
        @cloud_guard_decorator(minimum_trust_score=0.5)
        async def task(request: Request):
            agent = request.state.cloud_agent
            print(f"Verified: {agent['name']}")
    """
    if policy is None and kwargs:
        policy = TrustPolicy(**kwargs)

    def decorator(func):
        @wraps(func)
        async def wrapper(request: Request, *args, **kw):
            headers = dict(request.headers)
            result = verify_agent(headers, policy=policy)

            if not result["verified"]:
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "Cloud Identity verification failed",
                        "reason": result.get("reason"),
                    },
                )

            request.state.cloud_agent = result["agent"]
            request.state.cloud_verification = result
            return await func(request, *args, **kw)

        return wrapper

    return decorator


class CloudGuard(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware that verifies all incoming requests.
    Attach verified agent to request.state.cloud_agent.

    Example:
        app.add_middleware(CloudGuard)
        app.add_middleware(CloudGuard, policy=TrustPolicy(minimum_trust_score=0.5))
    """

    def __init__(self, app, policy: Optional[TrustPolicy] = None):
        super().__init__(app)
        self.policy = policy

    async def dispatch(self, request: Request, call_next):
        headers = dict(request.headers)
        result = verify_agent(headers, policy=self.policy)

        if result["verified"]:
            request.state.cloud_agent = result["agent"]
            request.state.cloud_verification = result
            response = await call_next(request)
            return response
        else:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Cloud Identity verification failed",
                    "reason": result.get("reason"),
                },
            )
