//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Some Lua and Python scripting glue to proxmark core.
//-----------------------------------------------------------------------------

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_PYTHON
//#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <wchar.h>
#endif

#include "cmdparser.h"    // command_t
#include "scripting.h"
#include "comms.h"
#include "cmdscript.h"
#include "cmdhfmf.h"
#include "pm3_binlib.h"
#include "pm3_bitlib.h"
#include "lualib.h"
#include "lauxlib.h"
#include "proxmark3.h"
#include "ui.h"
#include "fileutils.h"
#include "cliparser.h"    // cliparsing

#ifdef HAVE_LUA_SWIG
extern int luaopen_pm3(lua_State *L);
#endif

#ifdef HAVE_PYTHON
#ifdef HAVE_PYTHON_SWIG
extern PyObject *PyInit__pm3(void);
#endif // HAVE_PYTHON_SWIG

// Partly ripped from PyRun_SimpleFileExFlags
// but does not terminate client on sys.exit
// and print exit code only if != 0
static int Pm3PyRun_SimpleFileNoExit(FILE *fp, const char *filename) {
    PyObject *m, *d, *v;
    int set_file_name = 0, ret = -1;
    m = PyImport_AddModule("__main__");
    if (m == NULL)
        return -1;
    Py_INCREF(m);
    d = PyModule_GetDict(m);
    if (PyDict_GetItemString(d, "__file__") == NULL) {
        PyObject *f;
        f = PyUnicode_DecodeFSDefault(filename);
        if (f == NULL)
            goto done;
        if (PyDict_SetItemString(d, "__file__", f) < 0) {
            Py_DECREF(f);
            goto done;
        }
        if (PyDict_SetItemString(d, "__cached__", Py_None) < 0) {
            Py_DECREF(f);
            goto done;
        }
        set_file_name = 1;
        Py_DECREF(f);
    }
    v = PyRun_FileExFlags(fp, filename, Py_file_input, d, d, 1, NULL);
    if (v == NULL) {
        Py_CLEAR(m);
        if (PyErr_ExceptionMatches(PyExc_SystemExit)) {
            // PyErr_Print() exists if SystemExit so we've to handle it ourselves
            PyObject *ty = 0, *er = 0, *tr = 0;
            PyErr_Fetch(&ty, &er, &tr);
            long err = PyLong_AsLong(er);
            if (err) {
                PrintAndLogEx(WARNING, "\nScript terminated by " _YELLOW_("SystemExit %li"), err);
            } else {
                ret = 0;
            }
            Py_DECREF(ty);
            Py_DECREF(er);
            Py_DECREF(er);
            PyErr_Clear();
            goto done;
        } else {
            PyErr_Print();
        }
        goto done;
    }
    Py_DECREF(v);
    ret = 0;
done:
    if (set_file_name && PyDict_DelItemString(d, "__file__"))
        PyErr_Clear();
    Py_XDECREF(m);
    return ret;
}
#endif // HAVE_PYTHON

typedef enum {
    PM3_UNSPECIFIED,
    PM3_LUA,
    PM3_CMD,
#ifdef HAVE_PYTHON
    PM3_PY
#endif
} pm3_scriptfile_t;

static int CmdHelp(const char *Cmd);

#ifdef HAVE_PYTHON

#define PYTHON_LIBRARIES_WILDCARD  "?.py"

static int split(char *str, char **arr) {
    int begin_index = 0;
    int word_cnt = 0;

    while (1) {
        while (isspace(str[begin_index])) {
            ++begin_index;
        }
        if (str[begin_index] == '\0') {
            break;
        }
        int end_index = begin_index;
        while (str[end_index] && !isspace(str[end_index])) {
            ++end_index;
        }
        int len = end_index - begin_index;
        char *tmp = calloc(len + 1, sizeof(char));
        memcpy(tmp, &str[begin_index], len);
        arr[word_cnt++] = tmp;
        begin_index = end_index;
    }
    return word_cnt;
}

static void set_python_path(const char *path) {
    PyObject *syspath = PySys_GetObject("path");
    if (syspath == 0) {
        PrintAndLogEx(WARNING, "Python failed to getobject");
    }

    PyObject *pName = PyUnicode_FromString(path);
    if (PyList_Insert(syspath, 0, pName)) {
        PrintAndLogEx(WARNING, "Error inserting extra path into sys.path list");
    }

    if (PySys_SetObject("path", syspath)) {
        PrintAndLogEx(WARNING, "Error setting sys.path object");
    }
}

static void set_python_paths(void) {
    // Prepending to sys.path so we can load scripts from various places.
    // This means the following directories are in reverse order of
    // priority for search python modules.

    // Allow current working directory because it seems that's what users want.
    // But put it with lower search priority than the typical pm3 scripts directories
    // but still with a higher priority than the pip installed libraries to mimic
    // Python interpreter behavior. That should be confusing the users the least.
    set_python_path(".");
    const char *exec_path = get_my_executable_directory();
    if (exec_path != NULL) {
        // from the ./pyscripts/ directory
        char scripts_path[strlen(exec_path) + strlen(PYTHON_SCRIPTS_SUBDIR) + strlen(PYTHON_LIBRARIES_WILDCARD) + 1];
        strcpy(scripts_path, exec_path);
        strcat(scripts_path, PYTHON_SCRIPTS_SUBDIR);
        // strcat(scripts_path, PYTHON_LIBRARIES_WILDCARD);
        set_python_path(scripts_path);
    }

    const char *user_path = get_my_user_directory();
    if (user_path != NULL) {
        // from the $HOME/.proxmark3/pyscripts/ directory
        char scripts_path[strlen(user_path) + strlen(PM3_USER_DIRECTORY) + strlen(PYTHON_SCRIPTS_SUBDIR) + strlen(PYTHON_LIBRARIES_WILDCARD) + 1];
        strcpy(scripts_path, user_path);
        strcat(scripts_path, PM3_USER_DIRECTORY);
        strcat(scripts_path, PYTHON_SCRIPTS_SUBDIR);
        // strcat(scripts_path, PYTHON_LIBRARIES_WILDCARD);
        set_python_path(scripts_path);

    }

    if (exec_path != NULL) {
        // from the $PREFIX/share/proxmark3/pyscripts/ directory
        char scripts_path[strlen(exec_path) + strlen(PM3_SHARE_RELPATH) + strlen(PYTHON_SCRIPTS_SUBDIR) + strlen(PYTHON_LIBRARIES_WILDCARD) + 1];
        strcpy(scripts_path, exec_path);
        strcat(scripts_path, PM3_SHARE_RELPATH);
        strcat(scripts_path, PYTHON_SCRIPTS_SUBDIR);
        // strcat(scripts_path, PYTHON_LIBRARIES_WILDCARD);
        set_python_path(scripts_path);
    }
}
#endif

/**
* Generate a sorted list of available commands, what it does is
* generate a file listing of the script-directory for files
* ending with .lua
*/
static int CmdScriptList(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "script list",
                  "List available Lua, Cmd and Python scripts",
                  "script list"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    PrintAndLogEx(NORMAL, "\n" _YELLOW_("[ Lua scripts ]"));
    int ret = searchAndList(LUA_SCRIPTS_SUBDIR, ".lua");
    if (ret != PM3_SUCCESS)
        return ret;

    PrintAndLogEx(NORMAL, "\n" _YELLOW_("[ Cmd scripts ]"));
    ret = searchAndList(CMD_SCRIPTS_SUBDIR, ".cmd");
    if (ret != PM3_SUCCESS)
        return ret;
#ifdef HAVE_PYTHON
    PrintAndLogEx(NORMAL, "\n" _YELLOW_("[ Python scripts ]"));
    return searchAndList(PYTHON_SCRIPTS_SUBDIR, ".py");
#else
    return ret;
#endif
}

/**
 * @brief CmdScriptRun - executes a script file.
 * @param argc
 * @param argv
 * @return
 */
static int CmdScriptRun(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "script run",
                  "Run a Lua, Cmd or Python script. "
                  "If no extension it will search for lua/cmd/py extensions\n"
                  "Use `script list` to see available scripts",
                  "script run my_script -h\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_file1(NULL, NULL, "<filename>", "name of script to run"),
        arg_strx0(NULL, NULL, "<params>", "script parameters"),
        arg_param_end
    };

    int fnlen = 0;
    char filename[128] = {0};
    int arg_len = 0;
    char arguments[256] = {0};

    sscanf(Cmd, "%127s%n %255[^\n\r]%n", filename, &fnlen, arguments, &arg_len);

    // hack
    // since we don't want to use "-f"  for script filename,
    // and be able to send in parameters into script meanwhile
    // being able to "-h" here too.
    if ((strlen(filename) == 0) ||
            (strcmp(filename, "-h") == 0) ||
            (strcmp(filename, "--help") == 0)) {
        ctx->argtable = argtable;
        ctx->argtableLen = arg_getsize(argtable);
        CLIParserPrintHelp(ctx);
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }
    CLIParserFree(ctx);

    // try to detect a valid script file extension, case-insensitive
    char *extension_chk;
    extension_chk = str_dup(filename);
    str_lower(extension_chk);

    pm3_scriptfile_t ext = PM3_UNSPECIFIED;
    if (str_endswith(extension_chk, ".lua"))  {
        ext = PM3_LUA;
    } else if (str_endswith(extension_chk, ".cmd"))  {
        ext = PM3_CMD;
    }
#ifdef HAVE_PYTHON
    else if (str_endswith(extension_chk, ".py")) {
        ext = PM3_PY;
    }
#endif
    free(extension_chk);

    static uint8_t luascriptfile_idx = 0;
    char *script_path = NULL;
    if (((ext == PM3_LUA) || (ext == PM3_UNSPECIFIED)) && (searchFile(&script_path, LUA_SCRIPTS_SUBDIR, filename, ".lua", true) == PM3_SUCCESS)) {
        int error;
        if (luascriptfile_idx == MAX_NESTED_LUASCRIPT) {
            PrintAndLogEx(ERR, "too many nested scripts, skipping %s\n", script_path);
            free(script_path);
            return PM3_EMALLOC;
        }
        PrintAndLogEx(SUCCESS, "executing lua " _YELLOW_("%s"), script_path);
        PrintAndLogEx(SUCCESS, "args " _YELLOW_("'%s'"), arguments);

        luascriptfile_idx++;

        // create new Lua state
        lua_State *lua_state;
        lua_state = luaL_newstate();

        // load Lua libraries
        luaL_openlibs(lua_state);

        //Sets the pm3 core libraries, that go a bit 'under the hood'
        set_pm3_libraries(lua_state);

        //Add the 'bin' library
        set_bin_library(lua_state);

        //Add the 'bit' library
        set_bit_library(lua_state);
#ifdef HAVE_LUA_SWIG
        luaL_requiref(lua_state, "pm3", luaopen_pm3, 1);
#endif
        error = luaL_loadfile(lua_state, script_path);
        free(script_path);
        if (!error) {
            lua_pushstring(lua_state, arguments);
            lua_setglobal(lua_state, "args");

            //Call it with 0 arguments
            error = lua_pcall(lua_state, 0, LUA_MULTRET, 0); // once again, returns non-0 on error,
        }
        if (error) { // if non-0, then an error
            // the top of the stack should be the error string
            if (!lua_isstring(lua_state, lua_gettop(lua_state)))
                PrintAndLogEx(FAILED, "error - but no error (?!)");

            // get the top of the stack as the error and pop it off
            const char *str = lua_tostring(lua_state, lua_gettop(lua_state));
            lua_pop(lua_state, 1);
            PrintAndLogEx(FAILED, _RED_("error") " - %s", str);
        }

        //luaL_dofile(lua_state, buf);
        // close the Lua state
        lua_close(lua_state);
        luascriptfile_idx--;
        PrintAndLogEx(SUCCESS, "\nfinished " _YELLOW_("%s"), filename);
        return PM3_SUCCESS;
    }

    if (((ext == PM3_CMD) || (ext == PM3_UNSPECIFIED)) && (searchFile(&script_path, CMD_SCRIPTS_SUBDIR, filename, ".cmd", true) == PM3_SUCCESS)) {

        PrintAndLogEx(SUCCESS, "executing Cmd " _YELLOW_("%s"), script_path);
        PrintAndLogEx(SUCCESS, "args " _YELLOW_("'%s'"), arguments);

        int ret = push_cmdscriptfile(script_path, true);
        if (ret != PM3_SUCCESS)
            PrintAndLogEx(ERR, "could not open " _YELLOW_("%s") "...", script_path);
        free(script_path);
        return ret;
    }

    /*
    For apt (Ubuntu, Debian...):
        sudo apt-get install python3-dev  # for python3.x installs

    For yum (CentOS, RHEL...):
        sudo yum install python3-devel   # for python3.x installs

    For dnf (Fedora...):
        sudo dnf install python3-devel  # for python3.x installs

    For zypper (openSUSE...):
        sudo zypper in python3-devel  # for python3.x installs

    For apk (Alpine...):

        # This is a departure from the normal Alpine naming
        # scheme, which uses py2- and py3- prefixes

        sudo apk add python3-dev  # for python3.x installs

    For apt-cyg (Cygwin...):
        apt-cyg install python3-devel  # for python3.x installs
    */

#ifdef HAVE_PYTHON

    if (((ext == PM3_PY)  || (ext == PM3_UNSPECIFIED)) && (searchFile(&script_path, PYTHON_SCRIPTS_SUBDIR, filename, ".py", true) == PM3_SUCCESS)) {

        PrintAndLogEx(SUCCESS, "executing python " _YELLOW_("%s"), script_path);
        PrintAndLogEx(SUCCESS, "args " _YELLOW_("'%s'"), arguments);

#ifdef HAVE_PYTHON_SWIG
        // hook Proxmark3 API
        PyImport_AppendInittab("_pm3", PyInit__pm3);
#endif
#if PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 10
        Py_Initialize();
#else
        PyConfig py_conf;
        // We need to use Python mode instead of isolated to avoid breaking stuff.
        PyConfig_InitPythonConfig(&py_conf);
        // Let's still make things bit safer by being as close as possible to isolated mode.
        py_conf.configure_c_stdio = -1;
        py_conf.faulthandler = 0;
        py_conf.use_hash_seed = 0;
        py_conf.install_signal_handlers = 0;
        py_conf.parse_argv = 0;
        py_conf.user_site_directory = 1;
        py_conf.use_environment = 0;
#endif

        //int argc, char ** argv
        char *argv[128];
        argv[0] = filename;
        int argc = split(arguments, &argv[1]);
#if PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 10
        wchar_t *py_args[argc + 1];
        for (int i = 0; i <= argc; i++) {
            py_args[i] = Py_DecodeLocale(argv[i], NULL);
        }

        PySys_SetArgv(argc + 1, py_args);
#else
        // The following line will implicitly pre-initialize Python
        PyConfig_SetBytesArgv(&py_conf, argc + 1, argv);

        // We disallowed in py_conf environment variables interfering with python interpreter's behavior.
        // Let's manually enable the ones we truly need.
        // This is required by Proxspace to work with an isolated Python configuration
        PyConfig_SetBytesString(&py_conf, &py_conf.home, getenv("PYTHONHOME"));
        // This is required for allowing `import pm3` in python scripts
        PyConfig_SetBytesString(&py_conf, &py_conf.pythonpath_env, getenv("PYTHONPATH"));

        Py_InitializeFromConfig(&py_conf);

        // clean up
        PyConfig_Clear(&py_conf);
#endif
        for (int i = 0; i < argc; ++i) {
            free(argv[i + 1]);
        }

        // setup search paths.
        set_python_paths();

        FILE *f = fopen(script_path, "r");
        if (f == NULL) {
            PrintAndLogEx(ERR, "Could open file " _YELLOW_("%s"), script_path);
            free(script_path);
            return PM3_ESOFT;
        }
        int ret = Pm3PyRun_SimpleFileNoExit(f, filename);
#if PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 10
        // Py_DecodeLocale() allocates memory that needs to be free'd
        for (int i = 0; i < argc + 1; i++) {
            PyMem_RawFree(py_args[i]);
        }
#endif
        Py_Finalize();
        free(script_path);
        if (ret) {
            PrintAndLogEx(WARNING, "\nfinished " _YELLOW_("%s") " with exception", filename);
            return PM3_ESOFT;
        } else {
            PrintAndLogEx(SUCCESS, "\nfinished " _YELLOW_("%s"), filename);
            return PM3_SUCCESS;
        }
    }
#endif

    // file not found, let's search again to display the error messages
    int ret = PM3_EUNDEF;
    if (ext == PM3_LUA)
        ret = searchFile(&script_path, LUA_SCRIPTS_SUBDIR, filename, ".lua", false);
    else if (ext == PM3_CMD)
        ret = searchFile(&script_path, CMD_SCRIPTS_SUBDIR, filename, ".cmd", false);
#ifdef HAVE_PYTHON
    else if (ext == PM3_PY)
        ret = searchFile(&script_path, PYTHON_SCRIPTS_SUBDIR, filename, ".py", false);
    else if (ext == PM3_UNSPECIFIED)
        PrintAndLogEx(FAILED, "Error - can't find %s.[lua|cmd|py]", filename);
#else
    else if (ext == PM3_UNSPECIFIED)
        PrintAndLogEx(FAILED, "Error - can't find %s.[lua|cmd]", filename);
#endif
    free(script_path);
    return ret;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,          AlwaysAvailable, "This help"},
    {"list",  CmdScriptList,    AlwaysAvailable, "List available scripts"},
    {"run",   CmdScriptRun,     AlwaysAvailable, "<name> - execute a script"},
    {NULL, NULL, NULL, NULL}
};

/**
 * Shows some basic help
 * @brief CmdHelp
 * @param Cmd
 * @return
 */
static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
#ifdef HAVE_PYTHON
    PrintAndLogEx(NORMAL, "This is a feature to run Lua/Cmd/Python scripts. You can place scripts within the luascripts/cmdscripts/pyscripts folders. ");
#else
    PrintAndLogEx(NORMAL, "This is a feature to run Lua/Cmd scripts. You can place scripts within the luascripts/cmdscripts folders. ");
#endif
    return PM3_SUCCESS;
}

/**
 * Finds a matching script-file
 * @brief CmdScript
 * @param Cmd
 * @return
 */
int CmdScript(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

