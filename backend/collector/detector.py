def detect_threat(log):

    event = log["event_type"]

    if event == "LOGON_FAILURE":
        return "MEDIUM"

    elif event == "PROCESS_CREATED":
        return "LOW"

    elif event == "NETWORK_CONNECTION":

        ip = log["destination_ip"]

        if ip and ip != "127.0.0.1":
            return "MEDIUM"

        return "LOW"

    elif event == "FILE_ACCESS":
        return "LOW"

    elif event == "LOCAL_GROUP_ENUMERATION":
        return "MEDIUM"

    return "LOW"