import abc

import json
from parser import get_parsed_data_json, get_parsed_data_csv, CSV_HEADER, bar


class AbstractBuffer:
    def __init__(self):
        self.buffer = []

    def append(self, json_obj):
        print(f"{json_obj['filename']} scanned")
        self.buffer.append(json_obj)

    @abc.abstractmethod
    def flush(self):
        return self.buffer

    def __str__(self):
        return "\n".join(str(v) for v in self.buffer)


class CSVBuffer(AbstractBuffer):
    def flush(self):
        result = "\t".join(CSV_HEADER) + "\n"
        result += "\n".join(get_parsed_data_csv(json_obj) for json_obj in self.buffer)
        return result


class JSONBuffer(AbstractBuffer):
    def flush(self):
        result = []
        for json_obj in self.buffer:
            result.append(get_parsed_data_json(json_obj))
        return json.dumps(result, indent=4)


class STDOUTBuffer(AbstractBuffer):
    def append(self, json_obj):
        print(json_obj["filename"] + " scanned")
        print(bar(get_parsed_data_json(json_obj)))

    def flush(self):
        pass
