from __future__ import annotations
import struct, sys, traceback
try:
    import pythoncom
    from win32com.client import Dispatch, VARIANT
except Exception:
    print("PYWIN32_EXACT_IMPORT=FAIL")
    traceback.print_exc()
    raise SystemExit(10)

pythoncom.CoInitialize()
try:
    errors=[]
    for progid in ("DAO.DBEngine.36", "DAO.DBEngine.35"):
        try:
            eng=Dispatch(progid)
            print("DAO_PYTHON_PROBE=PASS")
            print("PYTHON_BITS=", struct.calcsize("P")*8, sep="")
            print("PROGID=", progid, sep="")
            print("DAO_VERSION=", getattr(eng,"Version","?"), sep="")
            raise SystemExit(0)
        except Exception as e:
            errors.append((progid, repr(e)))
    print("DAO_PYTHON_PROBE=FAIL")
    print("PYTHON_BITS=", struct.calcsize("P")*8, sep="")
    print("PYTHON=", sys.executable, sep="")
    for progid,err in errors:
        print(progid+"="+err)
    raise SystemExit(20)
finally:
    pythoncom.CoUninitialize()
