################################################################################
#
# CLEAN ROOM MODULE
#
# This module is classified as a "Clean Room" module and is subject to
# restrictions on what it may import.
#
# Clean Room can only use the base python libraries
################################################################################

import io
import logging
import os
import select
import shlex
import subprocess
import sys

def which(program):
    """
    Examine the ``PATH`` environment variable to determine the location for the
    specified program. If it can not be found None is returned. This is
    fundamentally similar to the Unix utility of the same name.
    :param str program: The name of the program to search for.
    :return: The absolute path to the program if found.
    :rtype: str
    """
    is_exe = lambda fpath: (os.path.isfile(fpath) and os.access(fpath, os.X_OK))
    for path in os.environ['PATH'].split(os.pathsep):
        path = path.strip('"')
        exe_file = os.path.join(path, program)
        if is_exe(exe_file):
            return exe_file
    if is_exe(program):
        return os.path.abspath(program)
    return None