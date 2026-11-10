"""AWS IAM policy over-privilege analyzer."""

from .policy import load_policy, iter_statements
from .checks import check_policy
from .report import summarize, render_text, render_json

__all__ = ["load_policy", "iter_statements", "check_policy",
           "summarize", "render_text", "render_json"]
