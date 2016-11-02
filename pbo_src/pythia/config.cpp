class CfgPatches {
    class PY3_Pythia {
        units[] = {};
        weapons[] = {};
        requiredVersion = 1.64;
        requiredAddons[] = {};
        bullshit = "test";

        // author = AUTHOR_STR;
        // authors[] = AUTHOR_ARR;
        // authorUrl = AUTHOR_URL;
        // version = VERSION;
        // versionStr = QUOTE(VERSION);
        // versionAr[] = {VERSION_AR};
    };
};

class CfgFunctions {
      class PY3 {
            class Extension {
                file = "\@pythia\addons\pythia";
                class callExtension {
                    recompile = 1;
                };
                bullshit = "test";
            };
      };
};