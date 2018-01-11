class CfgPatches {
    class PY3_Pythia {
        units[] = {};
        weapons[] = {};
        requiredVersion = 1.66;
        requiredAddons[] = {};

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
                    header = -1;
                    recompile = 1;
                };

                class showMessage { header = -1; };

                class callEx {
                    recompile = 1;
                };

                class extensionTest {
                    preStart = 1;
                    preInit = 1;
                };
            };
      };
};
