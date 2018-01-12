/*
    Function:       PY3_fnc_showMessage
    Author:         Adanteh
    Description:    Shows a message in systemchat and does logging
    Example:        ["module.submodule.function_name", ["arg1", "arg2", 3]] call py3_fnc_callExtension;

*/

diag_log format ["[@Pythia] - Output: '%1'", _this];
systemChat _this;
if (is3Den) then {
    [_this, 1] call BIS_fnc_3DENNotification;
};
