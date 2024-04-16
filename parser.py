def get_parsed_data_json(json_obj):
    output = {}

    output["name"] = json_obj.get("meaningful_name")
    output["stats"] = json_obj.get("last_analysis_stats")
    output["engine_detected"] = {}

    for engine in json_obj.get("last_analysis_results").keys():
        if json_obj.get("last_analysis_results").get(engine).get("category") != "undetected":
            output.get("engine_detected")[engine] = {}
            output.get("engine_detected")[engine]["category"] = json_obj.get(
                "last_analysis_results").get(engine).get("category")
            output.get("engine_detected")[engine]["result"] = json_obj.get(
                "last_analysis_results").get(engine).get("result")

    output["votes"] = json_obj.get("total_votes")
    output["hash"] = {"sha1": json_obj.get(
        "sha1"), "sha254": json_obj.get("sha256")}
    output["size"] = json_obj.get("size")
    return output


CSV_HEADER = [
    "filename",
    "path",
    "vt_meaningful_name",
    "vt_malicious",
    "vt_suspicious",
    "vt_undetected",
    "vt_harmless",
    "vt_timeout",
    "vt_confirmed-timeout",
    "vt_failure",
    "vt_type-unsupported",
    "vt_votes_harmless",
    "vt_votes_malicious",
    "size",
    "sha1",
    "sha256"
]


def get_parsed_data_csv(json_obj):
    buffer = []

    buffer.append(json_obj.get("filename"))
    buffer.append(json_obj.get("path"))

    buffer.append(json_obj.get("meaningful_name"))

    stats = json_obj.get("last_analysis_stats")
    buffer.append(stats.get("malicious"))
    buffer.append(stats.get("suspicious"))
    buffer.append(stats.get("undetected"))
    buffer.append(stats.get("harmless"))
    buffer.append(stats.get("timeout"))
    buffer.append(stats.get("confirmed-timeout"))
    buffer.append(stats.get("failure"))
    buffer.append(stats.get("type-unsupported"))

    votes = json_obj.get("total_votes")
    buffer.append(votes.get("harmless"))
    buffer.append(votes.get("malicious"))

    buffer.append(json_obj.get("size"))
    buffer.append(json_obj.get("sha1"))
    buffer.append(json_obj.get("sha256"))
    return "\t".join(str(v) for v in buffer)


def bar(parsed_response):
    """
    The function returns a bar to visually represent the engine
    detection.

    :param parsed_response: parsed dict/json from parse_response() function
    :return: result (type: str)
    """
    total = 72
    undetected = parsed_response.get("stats").get("undetected")
    detection = f"{'@' * undetected}{' ' * (total - undetected)}"
    result = f"+{'-' * total}+\n|{detection}| {undetected}/{total} did not detect\n+{'-' * total}+"
    return result


if __name__ == "__main__":
    import json

    with open('test_data.json', 'r') as f:
        data = json.load(f)
        print(get_parsed_data_csv(data))
