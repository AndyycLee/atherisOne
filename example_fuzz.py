import atheris
import sys
import json

@atheris.instrument_func
def TestOneInput(data):
    try:
        json.loads(data.decode("utf-8", errors="ignore"))
    except Exception:
        pass  # Ignore exceptions, just looking for crashes

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
