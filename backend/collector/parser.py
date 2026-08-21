import re
from datetime import datetime
from zoneinfo import ZoneInfo


# ============================================================
# Event ID Mapping
# ============================================================

EVENT_TYPES = {

    # Authentication
    4624: "LOGON_SUCCESS",
    4625: "FAILED_LOGIN",

    # File activity
    4663: "FILE_ACCESS",

    # Process activity
    4688: "PROCESS_CREATED",

    # User account activity
    4720: "USER_CREATED",
    4722: "USER_ENABLED",
    4723: "PASSWORD_CHANGED",
    4724: "PASSWORD_RESET",
    4725: "USER_DISABLED",
    4726: "USER_DELETED",

    # Group activity
    4732: "ADMIN_GROUP_ADDED",
    4733: "ADMIN_GROUP_REMOVED",

    # Reconnaissance
    4798: "LOCAL_GROUP_ENUMERATION",

    # Network activity
    5156: "NETWORK_CONNECTION",
    5158: "NETWORK_BIND"
}


# ============================================================
# Time Helper
# ============================================================

def normalize_timestamp(value):
    """
    Convert Windows PowerShell timestamp to:
    YYYY-MM-DD HH:MM:SS

    Example:
        /Date(1785247847657)/

    becomes:
        2026-07-28 00:00:47
    """

    if not value:
        return ""

    value_str = str(value)

    # --------------------------------------------------------
    # PowerShell /Date(...)/ format
    # --------------------------------------------------------

    match = re.search(
        r"/Date\((\d+)\)/",
        value_str
    )

    if match:

        milliseconds = int(match.group(1))

        dt = datetime.fromtimestamp(
            milliseconds / 1000,
            tz=ZoneInfo("Asia/Kolkata")
        )

        return dt.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    # --------------------------------------------------------
    # Normal datetime string
    # --------------------------------------------------------

    return value_str


# ============================================================
# Extract Helper
# ============================================================

def extract(patterns, text):
    """
    Try multiple regular-expression patterns.

    Returns the first valid extracted value.
    """

    if not text:
        return ""

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE | re.DOTALL
        )

        if match:

            value = match.group(1).strip()

            # Remove common Windows placeholder values
            if value in [
                "",
                "-",
                "(null)",
                "N/A"
            ]:
                continue

            return value

    return ""


# ============================================================
# Parse Windows Security Event
# ============================================================

def parse_event(event):

    message = event.get(
        "Message",
        ""
    )

    event_id = event.get(
        "Id",
        0
    )

    # --------------------------------------------------------
    # Convert Event ID safely to integer
    # --------------------------------------------------------

    try:
        event_id = int(event_id)
    except (
        ValueError,
        TypeError
    ):
        event_id = 0

    # --------------------------------------------------------
    # Create normalized log
    # --------------------------------------------------------

    log = {

        "record_id": event.get(
            "RecordId",
            0
        ),

        "timestamp": normalize_timestamp(
            event.get(
                "TimeCreated",
                ""
            )
        ),

        "event_type": EVENT_TYPES.get(
            event_id,
            "OTHER"
        ),

        "user": "",

        "hostname": event.get(
            "MachineName",
            ""
        ),

        "source_ip": "",

        "destination_ip": "",

        "process": "",

        "file_path": "",

        "severity": event.get(
            "LevelDisplayName",
            ""
        ),

        "raw_log": message
    }


    # ========================================================
    # USER
    # ========================================================

    log["user"] = extract(

        [

            # Event 4624
            r"New Logon:.*?Account Name:\s*([^\r\n]+)",

            # Event 4625
            r"Account For Which Logon Failed:.*?Account Name:\s*([^\r\n]+)",

            # Event 4688 / creator information
            r"Creator Subject:.*?Account Name:\s*([^\r\n]+)",

            # Generic User field
            r"User:.*?Account Name:\s*([^\r\n]+)",

            # Subject account
            r"Subject:.*?Account Name:\s*([^\r\n]+)",

            # Generic fallback
            r"Account Name:\s*([^\r\n]+)"

        ],

        message
    )


    # ========================================================
    # TARGET USER
    # ========================================================

    target_user = extract(

        [

            r"Target Account:.*?Account Name:\s*([^\r\n]+)",

            r"Target Account Name:\s*([^\r\n]+)",

            r"Target User Name:\s*([^\r\n]+)",

            r"Member Name:\s*([^\r\n]+)",

            r"New Account Name:\s*([^\r\n]+)"

        ],

        message
    )


    # --------------------------------------------------------
    # For account-management events, target user is more
    # useful than the subject user.
    # --------------------------------------------------------

    if target_user:

        log["user"] = target_user


    # ========================================================
    # PROCESS
    # ========================================================

    log["process"] = extract(

        [

            r"New Process Name:\s*([^\r\n]+)",

            r"Process Name:\s*([^\r\n]+)",

            r"Application Name:\s*([^\r\n]+)"

        ],

        message
    )


    # ========================================================
    # FILE PATH
    # ========================================================

    log["file_path"] = extract(

        [

            r"Object Name:\s*([^\r\n]+)"

        ],

        message
    )


    # ========================================================
    # SOURCE IP
    # ========================================================

    log["source_ip"] = extract(

        [

            r"Source Address:\s*([^\r\n]+)",

            r"Source Network Address:\s*([^\r\n]+)"

        ],

        message
    )


    # ========================================================
    # DESTINATION IP
    # ========================================================

    log["destination_ip"] = extract(

        [

            r"Destination Address:\s*([^\r\n]+)"

        ],

        message
    )


    # ========================================================
    # Return normalized event
    # ========================================================

    return log
