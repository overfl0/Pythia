/*
 *	File: fn_extensionTest.sqf
 *	Author: Adanteh
 *	Tests if the pythia extension works as expected
 */

private _result = ["pythia.test"] call py3_fnc_callExtension;
if !(_result isEqualTo "OK") exitWith {
	diag_log format ["ERROR: @Pythia mod loaded, but Pythia.dll not loaded!"];
	[false, "ERROR: @Pythia mod loaded, but Pythia.dll not loaded!"];
};

private _result = ["pythia.ping", "pong"] call py3_fnc_callExtension;
if !(_result isEqualTo ["pong"]) exitWith {
	diag_log format ["ERROR: @Pythia mod loaded, but error in Pythia.dll: '%1'", _result];
	[false, "ERROR: @Pythia mod loaded, but error in Pythia.dll"];
};

diag_log format ["@Pythia mod and extension loaded a-okay"];
[true, "@Pythia mod and extension loaded a-okay"];
