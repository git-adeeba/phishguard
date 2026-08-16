import json
import os


# ------------------------------------------------------------
# STORAGE FILE
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

HISTORY_FILE = os.path.join(
    BASE_DIR,
    "scan_history.json"
)


# ------------------------------------------------------------
# LOAD HISTORY
# ------------------------------------------------------------

def load_scan_history():

    if not os.path.exists(HISTORY_FILE):
        return []

    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

            if isinstance(data, list):
                return data

            return []

    except Exception:

        return []


# ------------------------------------------------------------
# SAVE HISTORY
# ------------------------------------------------------------

def save_scan_history(history):

    try:

        temp_file = HISTORY_FILE + ".tmp"

        with open(
            temp_file,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                history,
                file,
                indent=4,
                ensure_ascii=False
            )

        os.replace(
            temp_file,
            HISTORY_FILE
        )

    except Exception as e:

        print(
            f"Could not save scan history: {e}"
        )


# ------------------------------------------------------------
# ADD SCAN
# ------------------------------------------------------------

def add_scan(scan_record):

    history = load_scan_history()

    history.append(scan_record)

    save_scan_history(history)

    return history