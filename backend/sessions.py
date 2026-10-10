"""Agent sessions and administrator controls (Stage 9).

Session lifecycle (active, paused, terminated, completed), the task context
set by the backend from the inbox item, and the admin actions: stop,
continue, HR access, and approve or deny a held email. Protection mode is
fixed when a session is created. Continue never releases withheld content and
a hard deny can never be approved.
"""
