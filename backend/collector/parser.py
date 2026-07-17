import re

# ----------------------------
# Event ID Mapping
# ----------------------------

EVENT_TYPES = {
    4624: "LOGON_SUCCESS",
    4625: "LOGON_FAILURE",
    4663: "FILE_ACCESS",
    4688: "PROCESS_CREATED",
    4798: "LOCAL_GROUP_ENUMERATION",
    5156: "NETWORK_CONNECTION",
    5158: "NETWORK_BIND"
}


# ----------------------------
# Extract helper
# ----------------------------

def extract(patterns, text):
    """
    Try multiple regex patterns.
    Return the first matching value.
    """

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)

        if match:
            return match.group(1).strip()

    return ""


# ----------------------------
# Parse Windows Event
# ----------------------------

def parse_event(event):

    message = event.get("Message", "")

    event_id = event.get("Id", 0)

    log = {
        "timestamp": str(event.get("TimeCreated", "")),
        "event_type": EVENT_TYPES.get(event_id, "OTHER"),
        "user": "",
        "hostname": event.get("MachineName", ""),
        "source_ip": "",
        "destination_ip": "",
        "process": "",
        "file_path": "",
        "severity": event.get("LevelDisplayName", ""),
        "raw_log": message
    }

    # ----------------------------
    # USER
    # ----------------------------

    log["user"] = extract([

        r"New Logon:.*?Account Name:\s*([^\r\n]+)",

        r"Creator Subject:.*?Account Name:\s*([^\r\n]+)",

        r"User:.*?Account Name:\s*([^\r\n]+)",

        r"Subject:.*?Account Name:\s*([^\r\n]+)",

        r"Account Name:\s*([^\r\n]+)"

    ], message)


    # ----------------------------
    # PROCESS
    # ----------------------------

    log["process"] = extract([

        r"New Process Name:\s*([^\r\n]+)",

        r"Process Name:\s*([^\r\n]+)",

        r"Application Name:\s*([^\r\n]+)"

    ], message)


    # ----------------------------
    # FILE PATH
    # ----------------------------

    log["file_path"] = extract([

        r"Object Name:\s*([^\r\n]+)"

    ], message)


    # ----------------------------
    # SOURCE IP
    # ----------------------------

    log["source_ip"] = extract([

        r"Source Address:\s*([^\r\n]+)",

        r"Source Network Address:\s*([^\r\n]+)"

    ], message)


    # ----------------------------
    # DESTINATION IP
    # ----------------------------

    log["destination_ip"] = extract([

        r"Destination Address:\s*([^\r\n]+)"

    ], message)


    return log