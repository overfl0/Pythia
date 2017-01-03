/*
 *	File: fn_callExtension.sqf
 *	Author: Adanteh
 *	Describe your function
 *
 *	Example:
 *	[["foo"]] call py3_fnc_callExtension;

 *  test = ([["foo"]] call compile preprocessFileLineNumbers "\@pythia\addons\pythia\fn_callExtension.sqf")
 */

#define SQF_DEVELOPMENT 1

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

private _result = "Pythia" callExtension (str _this);
if (_result == "") exitWith {
	(format ["Extension output is empty"]) call _fnc_showHint;
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
    private _stitchID = parseNumber (_result select [6, count _result - 7]);
    while { (_result != "") } do {
        _result = "Pythia" callExtension (str ["pythia.multipart", _stitchID]);
        _returnStiched = _returnStiched + _result;
    };
    _result = _returnStiched;
    _returnCode = _result select [2,1];
};

if (_returnCode == "e") exitWith {
    (format ["An error occurred: %1", (_result select [6, count _result - 7])]) call _fnc_showHint;
	[];
};

if (_returnCode == "s") then {
    (call compile _result);
};

if (_returnCode == "r") exitWith {
    (call compile _result) select 1;
};

[]
