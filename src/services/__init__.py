# Services module
from .commit_analyzer import CommitAnalyzer
from .schedule_recommender import ScheduleRecommender

# ScheduleExecutor requires APScheduler, import conditionally
try:
    from .schedule_executor import ScheduleExecutor
    __all__ = ["CommitAnalyzer", "ScheduleRecommender", "ScheduleExecutor"]
except ImportError:
    __all__ = ["CommitAnalyzer", "ScheduleRecommender"]
