# Services module
#
# NOTE: ScheduleRecommender and ScheduleExecutor are NOT imported here to avoid
# circular imports. They depend on src.ai_agent which depends on src.services
# (via prompt_loader). Import them directly where needed:
#   from src.services.schedule_recommender import ScheduleRecommender
#   from src.services.schedule_executor import ScheduleExecutor
from .commit_analyzer import CommitAnalyzer

__all__ = ["CommitAnalyzer"]
