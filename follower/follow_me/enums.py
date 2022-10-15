from enum import Enum


class TimeInterval(Enum):
    three_hours = "3 hr"
    six_hours = "6 hr"
    twelve_hours = "12 hr"


class SetupStatus(Enum):
    active = "Active"
    disabled = "Disabled"
