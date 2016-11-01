/*
 *	File: fn_callExtension.sqf
 *	Author: Adanteh
 *	Describe your function
 *
 *	Example:
 *	[["foo"]] call py3_fnc_callExtension;

 *  test = ([["foo"]] call compile preprocessFileLineNumbers "\@pythia\addons\pythia\fn_callExtension.sqf")
 */

params ["_arguments"];

#define DEVMODE true
#ifndef DEVMODE
	#define DEVMODE false
#endif

if (DEVMODE && {isNil "_nest"}) exitWith {
	private _nest = true;
	_return = [_arguments] call compile preprocessFileLineNumbers "\@pythia\addons\pythia\fn_callExtension.sqf";
	_return;
};

private _fnc_showHint = {
	if (is3Den) then {
		[_this, 1] call BIS_fnc_3DENNotification;
	} else {
		hint _this;
	};
};

private _result = "Pythia" callExtension (str _arguments);
private _resultCompile = call compile _result;
if ((isNil "_resultCompile") || {!(_resultCompile isEqualType [])}) exitWith {
	(format ["Extension output is not array"]) call _fnc_showHint;
	[];
};

if ((_resultCompile select 0) == "e") exitWith {
    (format ["An error occurred:\n %1", (_resultCompile select 1)]) call _fnc_showHint;
	[];
};

(_resultCompile select 1)
