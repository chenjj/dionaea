#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
#* 
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#* 
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#* 
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#* 
#* 
#*             contact nepenthesdev@gmail.com  
#*
#*******************************************************************************/

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

from distutils import sysconfig

# The SlackWare Diaries ...
# we do not want python2.x to add its -lpython2.x to the linker 
# even if Py_ENABLE_SHARED is 1
# therefore we have to adjust the global Py_ENABLE_SHARED value in the 
# distutils.sysconfig._config_vars dict
# the proper fix would be not using py2 to build the module but py3 instead
# thanks to pyllyukko for his incredible patience with me working this out
#if sysconfig.get_config_var('Py_ENABLE_SHARED') == 1:
#	sysconfig._config_vars['Py_ENABLE_SHARED'] = 0


cflags=''
cflags+='-I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include   -pthread -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include   -pthread -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include  ' # glib
cflags+=' '
cflags+='-I/opt/dionaea/include -DEV_COMPAT3=0 -fno-strict-aliasing' # libev
cflags+=' '
cflags+='-I/opt/dionaea/include/' #liblcfg
cflags+=' '
cflags+='-fPIC -I/opt/dionaea/include/python3.2m' # python
cflags+=' '
cflags+='-Wall -Werror'
cflags+=' '
cflags+='-g'

libs=''
libs+='-Wl,-rpath=/opt/dionaea/lib/ -L/usr/lib/x86_64-linux-gnu/ -Xlinker -export-dynamic -lm -lpthread -ldl  -lutil -lpython3.2m' # python



include_dir_dict = {}
extra_compile_dict = {}
for i in cflags.split():
	if i.startswith('-I'):
		include_dir_dict[i[2:]] = 1
	else:
		extra_compile_dict[i] = 1


library_dict = {}
library_dir_dict = {}
library_other_dict = {}

for i in libs.split():
	if i.startswith('-l'):
		library_dict[i[2:]] = 1
	elif i.startswith('-L'):
		library_dir_dict[i[2:]] = 1
	else:
		library_other_dict[i] = 1

ext_modules=[
	Extension("dionaea.core", 
		['binding.pyx', 'module.c', 'pyev/pyev.c'], 
		language="c",
		include_dirs=['../../include', '../../'] + [k for k in sorted(include_dir_dict)],
		extra_compile_args=[k for k in sorted(extra_compile_dict)],
		libraries=[k for k in sorted(library_dict)],
		library_dirs=[k for k in sorted(library_dir_dict)],
		extra_link_args=[k for k in sorted(library_other_dict)],
		undef_macros=[('NDEBUG')],
		define_macros=[('_GNU_SOURCE',None)]
	),
]

setup(
	name = 'dionaea',
	cmdclass = {'build_ext': build_ext},
	ext_modules = ext_modules,
) 

