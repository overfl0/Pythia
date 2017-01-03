

#define DEVMODE true
#ifndef DEVMODE
	#define DEVMODE false
#endif

if (DEVMODE && {isNil "_nest"}) exitWith {
	private _nest = true;
	_return = _this call compile preprocessFileLineNumbers "\@pythia\addons\pythia\fn_callEx.sqf";
	_return;
};

private _result = "Pythia" callExtension (str _this);
private _resultCompile = call compile _result;

// ['s', _continue_id, SQFcode]
while {(_resultCompile select 0) == "s"} do {
    private _continue_id = (_resultCompile select 1);
    private _code = compile (_resultCompile select 2);
    private _sqf_result = call _code;

    _result = "Pythia" callExtension (str(['Pythia.continue', _continue_id, _sqf_result]));
    _resultCompile = call compile _result;
};

//hint (["python.coroutines.test_coroutines"] call py3_fnc_callEx)
(_resultCompile select 1);

