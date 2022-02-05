/*_________
 /         \ LUA_plugin.tinyfiledialogs.cpp v3.8.3 [Nov 1, 2020] zlib licence
 |tiny file| LUA bindings created [2016] Copyright (c) 2016 Steven Johnson
 | dialogs | Copyright (c) 2014 - 2020 Guillaume Vareille http://ysengrin.com
 \____  ___/ http://tinyfiledialogs.sourceforge.net
      \|     git clone http://git.code.sf.net/p/tinyfiledialogs/code tinyfd
              ____________________________________________
             |                                            |
             |   email: tinyfiledialogs at ysengrin.com   |
             |____________________________________________|

If you like tinyfiledialogs, please upvote my stackoverflow answer
https://stackoverflow.com/a/47651444

- License -
This software is provided 'as-is', without any express or implied
warranty.  In no event will the authors be held liable for any damages
arising from the use of this software.
Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:
1. The origin of this software must not be misrepresented; you must not
claim that you wrote the original software.  If you use this software
in a product, an acknowledgment in the product documentation would be
appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
-----------

this file was contributed by Steven Johnson from the Corona SDK project
and is offered here under the same zlib license as tinyfiledialogs

-#include "CoronaLua.h" will typically be something like
extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

in a normal(i.e.non - Corona) program.
- For that matter, CORONA_EXPORT just hides the library exporting code.
- The "_plugin_" stuff is part of a signature used by Corona to dynamically load the entry point function, but might be out
of place in a non - Corona program.
*/


#include "CoronaLua.h"
#include "tinyfiledialogs.h"
#include <string.h>

#define STATIC_FILTER_COUNT 8

static int GetBool (lua_State * L, const char * key)
{
	lua_getfield(L, 1, key);// ..., bool

	int bval = lua_toboolean(L, -1);

	lua_pop(L, 1);	// ...

	return bval;
}

static const char * GetStrOrBlank (lua_State * L, const char * key, const char * blank = "")
{
	lua_getfield(L, 1, key);// ..., str?

	const char * str = blank;	// might be NULL, thus not using luaL_optstring

	if (!lua_isnil(L, -1)) str = luaL_checkstring(L, -1);

	lua_pop(L, 1);

	return str;
}

static int GetFilters (lua_State * L, const char *** filters)
{
	int nfilters = 0;

	lua_getfield(L, 1, "filter_patterns");	// ..., patts

	if (lua_istable(L, -1))
	{
		int n = lua_objlen(L, -1);

		if (n > STATIC_FILTER_COUNT) *filters = (const char **)lua_newuserdata(L, sizeof(const char *) * n);// ..., patts, filters

		for (int i = 1; i <= n; ++i, lua_pop(L, 1))
		{
			lua_rawgeti(L, -1, i);	// ..., patts[, filters], patt

			(*filters)[nfilters++] = luaL_checkstring(L, -1);
		}
	}

	else if (!lua_isnil(L, -1)) (*filters)[nfilters++] = luaL_checkstring(L, -1);

	return nfilters;
}

static int StringResponse (lua_State * L, const char * res)
{
	if (!res) lua_pushboolean(L, 0);// ..., false

	else lua_pushstring(L, res);// ..., res

	return 1;
}

static luaL_Reg tfd_funcs[] = {
	{
		"notifyPopup", [](lua_State * L)
		{
			luaL_checktype(L, 1, LUA_TTABLE);

			const char * title = GetStrOrBlank(L, "title");
			const char * message = GetStrOrBlank(L, "message");
			const char * icon_types[] = { "info", "warning", "error" };

			lua_getfield(L, 1, "icon_type"); // opts, icon_type

			const char * itype = icon_types[luaL_checkoption(L, -1, "info", icon_types)];

			lua_pushboolean(L, tinyfd_notifyPopup(title, message, itype));	// opts, icon_type

			return 1;
		}
	}, {
		"messageBox", [](lua_State * L)
		{
			luaL_checktype(L, 1, LUA_TTABLE);

			const char * title = GetStrOrBlank(L, "title");
			const char * message = GetStrOrBlank(L, "message");
			const char * dialog_types[] = { "ok", "okcancel", "yesno", "yesnocancel" };
			const char * icon_types[] = { "info", "warning", "error", "question" };

			lua_getfield(L, 1, "dialog_type");	// opts, dialog_type
			lua_getfield(L, 1, "icon_type");// opts, dialog_type, icon_type

			const char * dtype = dialog_types[luaL_checkoption(L, -2, "ok", dialog_types)];
			const char * itype = icon_types[luaL_checkoption(L, -1, "info", icon_types)];

			lua_pushboolean(L, tinyfd_messageBox(title, message, dtype, itype, GetBool(L, "default_okyes")));	// opts, dialog_type, icon_type, ok / yes

			return 1;
		}
	}, {
		"inputBox", [](lua_State * L)
		{
			luaL_checktype(L, 1, LUA_TTABLE);

			const char * title = GetStrOrBlank(L, "title");
			const char * message = GetStrOrBlank(L, "message");

			//
			lua_getfield(L, 1, "default_input");// opts, def_input

			const char * def_input;

			if (lua_type(L, -1) == LUA_TBOOLEAN && !lua_toboolean(L, -1)) def_input = NULL;

			else def_input = luaL_optstring(L, -1, "");

			return StringResponse(L, tinyfd_inputBox(title, message, def_input));	// opts, def_input, input
		}
	}, {
		"saveFileDialog", [](lua_State * L)
		{
			luaL_checktype(L, 1, LUA_TTABLE);

			const char * title = GetStrOrBlank(L, "title");
			const char * def_path_and_file = GetStrOrBlank(L, "default_path_and_file");
			const char * filter_description = GetStrOrBlank(L, "filter_description", NULL);
			const char * filter_array[STATIC_FILTER_COUNT] = { 0 }, ** filters = filter_array;
			int nfilters = GetFilters(L, &filters);	// opts, patts[, filters]

			return StringResponse(L, tinyfd_saveFileDialog(title, def_path_and_file, nfilters, filters, filter_description));	// opts, patts[, filters], file
		}
	}, {
		"openFileDialog", [](lua_State * L)
		{
			luaL_checktype(L, 1, LUA_TTABLE);

			//
			const char * title = GetStrOrBlank(L, "title");
			const char * def_path_and_file = GetStrOrBlank(L, "default_path_and_file");
			const char * filter_description = GetStrOrBlank(L, "filter_description", NULL);
			const char * filter_array[STATIC_FILTER_COUNT] = { 0 }, ** filters = filter_array;
			int allow_multiple_selects = GetBool(L, "allow_multiple_selects");
			int nfilters = GetFilters(L, &filters);	// opts, patts[, filters]

			//
			const char * files = tinyfd_openFileDialog(title, def_path_and_file, nfilters, nfilters ? filters : NULL, filter_description, allow_multiple_selects);

			if (!allow_multiple_selects || !files) return StringResponse(L, files);	// opts, patts[, filters], files?

			else
			{
				lua_newtable(L);// opts, patts[, filters], files

				char * from = (char *)files, * sep = from; // assign sep in order to pass first iteration

				for (int fi = 1; sep; ++fi)
				{
					sep = strchr(from, '|');

					if (sep)
					{
						lua_pushlstring(L, from, sep - from);	// opts, patts[, filters], files, file

						from = sep + 1;
					}

					else lua_pushstring(L, from);// opts, patts[, filters], files, file
				
					lua_rawseti(L, -2, fi);	// opts, patts[, filters], files = { ..., file }
				}
			}

			return 1;
		}
	}, {
		"selectFolderDialog", [](lua_State * L)
		{
			luaL_checktype(L, 1, LUA_TTABLE);

			const char * title = GetStrOrBlank(L, "title");
			const char * def_path = GetStrOrBlank(L, "default_path");

			return StringResponse(L, tinyfd_selectFolderDialog(title, def_path));	// opts, folder
		}
	}, {
	"colorChooser", [](lua_State * L)
		{
			luaL_checktype(L, 1, LUA_TTABLE);
			lua_settop(L, 1);	// opts
			lua_getfield(L, 1, "out_rgb");	// opts, out

			const char * title = GetStrOrBlank(L, "title");

			//
			unsigned char rgb[3];

			lua_getfield(L, 1, "rgb");	// opts, out, rgb

			const char * def_hex_rgb = NULL;

			if (lua_istable(L, 3))
			{
				lua_getfield(L, 3, "r");// opts, out, rgb, r
				lua_getfield(L, 3, "g");// opts, out, rgb, r, g
				lua_getfield(L, 3, "b");// opts, out, rgb, r, g, b

				for (int i = 1; i <= 3; ++i) rgb[i - 1] = (unsigned char)(luaL_checknumber(L, 3 + i) * 255.0);
			}

			else def_hex_rgb = luaL_optstring(L, 3, "#000000");

			const char * color = tinyfd_colorChooser(title, def_hex_rgb, rgb, rgb);

			if (color && lua_istable(L, 2))
			{
				for (int i = 0; i < 3; ++i) lua_pushnumber(L, (double)rgb[i] / 255.0);	// opts, out, rgb[, r, g, b], rout, gout, bout

				lua_setfield(L, 2, "b");// opts, out, rgb[, r, g, b], rout, gout
				lua_setfield(L, 2, "g");// opts, out, rgb[, r, g, b], rout
				lua_setfield(L, 2, "r");// opts, out, rgb[, r, g, b]
			}

			return StringResponse(L, color);// opts, out, rgb[, r, g, b], color
		}
	},
		{ NULL, NULL }
};

CORONA_EXPORT int luaopen_plugin_tinyfiledialogs(lua_State* L)
{
	lua_newtable(L);// t
	luaL_register(L, NULL, tfd_funcs);

	return 1;
}