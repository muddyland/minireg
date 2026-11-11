"""Admin API. Every route here requires an authenticated admin identity."""

from fastapi import APIRouter

from . import insights, management, risk

router = APIRouter(prefix="/api/admin", tags=["admin"])
router.include_router(management.router)
router.include_router(insights.router)
router.include_router(risk.router)

__all__ = ["router"]
