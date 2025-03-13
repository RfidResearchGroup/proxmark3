"""
Helper library to locate resources for pm3 scripts.

This module provides functionality to locate tools and dictionaries required
for pm3 scripts. It determines the paths based on the directory structure
and whether the script is being run in a development setup or an installed setup.

Functions:
    find_tool(tool_name):
        Finds the specified tool in the tools directory.
        Args:
            tool_name (str): The name of the tool to find.
        Returns:
            str: The full path to the tool if found, otherwise None.

    find_dict(dict_name):
        Find the specified dictionary in the dicts directory.
        Args:
            dict_name (str): The name of the dict to find.
        Returns:
            str: The full path to the dict if found, otherwise None.
"""

import os

# Install script can hardcode paths in the following variables
TOOLS_PATH = None
DICTS_PATH = None

if __name__ == "__main__":
    print("This is a library, don't use it as a script")
    exit()

DIR_PATH = os.path.dirname(os.path.abspath(__file__))

if TOOLS_PATH is None:
    if os.path.basename(os.path.dirname(DIR_PATH)) == 'client':
        # dev setup
        DEV_TOOLS_PATH = os.path.normpath(os.path.join(DIR_PATH, "..", "..", "tools", "mfc", "card_only"))
        if os.path.isdir(DEV_TOOLS_PATH):
            TOOLS_PATH = DEV_TOOLS_PATH

if TOOLS_PATH is None:
    # assuming installed without having defined TOOLS_PATH
    TEST_TOOLS_PATH = os.path.normpath(os.path.join(DIR_PATH, "..", "tools"))
    if os.path.isdir(TEST_TOOLS_PATH):
        TOOLS_PATH = TEST_TOOLS_PATH


if DICTS_PATH is None:
    DEV_DICTS_PATH = os.path.normpath(os.path.join(DIR_PATH, "..", "dictionaries"))
    if os.path.isdir(DEV_DICTS_PATH):
        DICTS_PATH = DEV_DICTS_PATH


def find_tool(tool_name):
    """Find the specified tool in the tools directory.

    Args:
        tool_name (str): The name of the tool to find.
    Returns:
        str: The full path to the tool if found, otherwise None.
    """
    if TOOLS_PATH is not None:
        tool = os.path.join(TOOLS_PATH, tool_name)
        if os.path.isfile(tool):
            return tool
        elif os.path.isfile(tool + ".exe"):
            return tool + ".exe"
    # if not found, search in the user PATH
    for path in os.environ["PATH"].split(os.pathsep):
        env_tool = os.path.join(path, tool_name)
        if os.path.isfile(env_tool):
            return env_tool
        elif os.path.isfile(env_tool + ".exe"):
            return env_tool + ".exe"
    raise FileNotFoundError(f"Cannot find {tool_name}, abort!")


def find_dict(dict_name):
    """Find the specified dictionary in the dicts directory.

    Args:
        dict_name (str): The name of the dict to find.
    Returns:
        str: The full path to the dict if found, otherwise None.
    """
    if DICTS_PATH is not None:
        dictionary = os.path.join(DICTS_PATH, dict_name)
        if os.path.isfile(dictionary):
            return dictionary
    raise FileNotFoundError(f"Cannot find {dict_name}, abort!")
