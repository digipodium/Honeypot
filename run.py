from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


APP_FILE = Path(__file__).with_name("app.py")
SPEC = spec_from_file_location("honeypot_web_app", APP_FILE)
MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
app = MODULE.app


if __name__ == "__main__":
    app.run(debug=True)
