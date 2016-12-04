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

private _resultCompile = call compile _result;
if !(_resultCompile isEqualType []) exitWith {
	(format ["Extension output is not array"]) call _fnc_showHint;
	[];
};

if ((_resultCompile select 0) == "e") exitWith {
    (format ["An error occurred:\n %1", (_resultCompile select 1)]) call _fnc_showHint;
	[];
};

(_resultCompile select 1)
