/*
    Function:       PY3_fnc_callExtension
    Author:         Adanteh
    Description:    Call extension function for pythia. Handles parsing input and output and giving proper error codes
    Example:        ["module.submodule.function_name", ["arg1", "arg2", 3]] call py3_fnc_callExtension;

*/

#ifdef SQF_DEVELOPMENT
	if (isNil "_nest") exitWith {
		private _nest = true;
		_return = _this call compile preprocessFileLineNumbers "\@pythia\addons\pythia\fn_callExtension.sqf";
		_return;
	};
#endif

private _fnc_showHint = {
	diag_log format ["[@Pythia] - Output: '%1'", _this];
	systemChat _this;
	if (is3Den) then {
		[_this, 1] call BIS_fnc_3DENNotification;
	};
};

params ["_functionName", ["_args", []]];
private _result = "Pythia" callExtension (str [_functionName, _args]);
if (_result == "") exitWith {
	(format ["Extension output is empty. One possible cause is BattlEye blocking the extension."]) call _fnc_showHint;
	[];
};

if (_result select [0, 1] != "[") exitWith {
	(format ["Extension output is not array"]) call _fnc_showHint;
	[];
};

private _returnCode = _result select [2,1];

// -- Multipart response. This stiches multiple callExtensions to get past the 10k char limit
if (_returnCode == "m") then {
    private _returnStiched = "";
    private _multipartString = call compile _result;
    private _stitchID = _multipartString param [1, 1, [1]];
    private _numberOfMessages = _multipartString param [2, 1, [1]];

    for "_i" from 1 to _numberOfMessages do {
        _result = "Pythia" callExtension (str ["pythia.multipart", _stitchID]);
        _returnStiched = _returnStiched + _result
    };
    _result = _returnStiched;
    _returnCode = _result select [2,1];
};

if (_returnCode == "e") exitWith {
    (format ["An error occurred: %1", (_result select [5, count _result - 7])]) call _fnc_showHint;
	[];
};

if (_returnCode == "s") then {
    (call compile _result);
};

if (_returnCode == "r") exitWith {
    (call compile _result) select 1;
};

[]
