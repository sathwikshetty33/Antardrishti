"""write the json schema of the current contract: python -m app.schema.export"""
import json
from pathlib import Path

from app.schema import v1


def main():
    s = v1.result.model_json_schema()
    s["$id"] = "https://github.com/sathwikshetty33/SIH/app/schema/result.v1.json"
    s["title"] = v1.schema_version
    s["description"] = (v1.__doc__ or "").strip()
    s["x-known-facts"] = v1.known_facts
    out = Path(__file__).with_name("result.v1.json")
    out.write_text(json.dumps(s, indent=1) + "\n")
    print(out)


if __name__ == "__main__":
    main()
