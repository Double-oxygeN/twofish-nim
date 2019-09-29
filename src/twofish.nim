# Copyright (c) 2019 Double-oxygeN
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

stderr.writeLine "\e[33m************************"
stderr.writeLine "'import twofish' is deprecated."
stderr.writeLine "Please use 'import twofish/twofish128', 'import twofish/twofish192' or 'import twofish/twofish256'."
stderr.writeLine "************************\e[0m"

import twofish/twofish128
export twofish128
