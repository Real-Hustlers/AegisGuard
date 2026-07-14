import json

def load_json_files(folder):

    all_data = []

    for json_file in folder.glob("*.json"):
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            all_data.append(data)

    # print(f"Loaded {len(all_data)} JSON files.")
    # print(all_data)

    return all_data