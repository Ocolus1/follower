from enum import Enum


class TimeInterval(Enum):
    ten_sec = "10 sec"
    twenty_sec = "20 sec"
    thirty_sec = "30 sec"


class SetupStatus(Enum):
    active = "Active"
    disabled = "Disabled"
