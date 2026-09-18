Option Explicit
Dim eng, ver
On Error Resume Next
Err.Clear
Set eng = CreateObject("DAO.DBEngine.36")
If Err.Number = 0 Then
  ver = "DAO.DBEngine.36"
Else
  Err.Clear
  Set eng = CreateObject("DAO.DBEngine.35")
  If Err.Number = 0 Then
    ver = "DAO.DBEngine.35"
  Else
    WScript.Echo "DAO_PROBE=FAIL"
    WScript.Echo "Neither DAO.DBEngine.36 nor DAO.DBEngine.35 is registered in this scripting host."
    WScript.Quit 2
  End If
End If
On Error GoTo 0
WScript.Echo "DAO_PROBE=PASS"
WScript.Echo "PROGID=" & ver
WScript.Echo "VERSION=" & eng.Version
