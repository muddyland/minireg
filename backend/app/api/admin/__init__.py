"""Admin API. Every route here requires an authenticated admin identity."""

from fastapi import APIRouter

from . import insights, management

router = APIRouter(prefix="/api/admin", tags=["admin"])
router.include_router(management.router)
router.include_router(insights.router)

__all__ = ["router"]
