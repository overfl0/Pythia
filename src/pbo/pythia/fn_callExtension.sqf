/*
    Function:       PY3_fnc_callExtension
    Author:         Adanteh
    Description:    Call extension function for pythia. Handles parsing input and output and giving proper error codes
    Example:        ["module.submodule.function_name", ["arg1", "arg2", 3]] call py3_fnc_callExtension;
                    ["pythia.ping",[1,2,3,4,5,6,7,8,9,10]] call py3_fnc_callExtension
                    ["python.coroutines.test_coroutines"] call py3_fnc_callExtension

*/

#ifdef SQF_DEVELOPMENT
	if (isNil "_nest") exitWith {
		private _nest = true;
        "py3_fnc_callExtension" call BIS_fnc_recompile;
		_return = _this call py3_fnc_callExtension;
		_return;
	};
#endif

private _result = "Pythia" callExtension (str _this);
if (_result == "") exitWith {
	"Extension output is empty. One possible cause is BattlEye blocking the extension." call PY3_fnc_showMessage;
	[];
};


if ((_result select [2,1]) isEqualTo "r") exitWith {
    (call compile _result) select 1;
};

while { (_result select [2,1]) isEqualTo "s" } do {
    private _resultCompile = call compile _result;
    _result = "Pythia" callExtension (str(["pythia.continue", [_resultCompile select 1, call compile (_resultCompile select 2)]]));
};

scopeName "py3";
while { true } do {
    switch (_result select [2,1]) do {

        // -- Multipart response. This stiches multiple callExtensions to get past the 10k char limit
        case "m": {
            private _returnStiched = "";
            private _multipartString = call compile _result;

            for "_i" from 1 to (_multipartString select 2) do {
                _result = "Pythia" callExtension (str ["pythia.multipart", _multipartString select 1]);
                _returnStiched = _returnStiched + _result
            };
            _result = _returnStiched;
        };

        case "r": {
            (call compile _result) select 1 breakOut "py3";
        };

        case "s": {
            while { (_result select [2,1]) isEqualTo "s" } do {
                private _resultCompile = call compile _result;
                _result = "Pythia" callExtension (str(["pythia.continue", [_resultCompile select 1, call compile (_resultCompile select 2)]]));
            };
        };

        case "e": {
            ("An error occurred: " + (_result select [5, count _result - 7])) call PY3_fnc_showMessage;
            [] breakOut "py3";
        };

        default {
            "Unknown return code" call PY3_fnc_showMessage;
            [] breakOut "py3";
        };
    };
};

[]
