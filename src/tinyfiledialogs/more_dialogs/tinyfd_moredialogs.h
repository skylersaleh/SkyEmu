/*_________
 /         \ tinyfiledialogs v3.8.8 [Apr 22, 2021] zlib licence
 |tiny file| 
 | dialogs | Copyright (c) 2014 - 2021 Guillaume Vareille http://ysengrin.com
 \____  ___/ http://tinyfiledialogs.sourceforge.net
      \|     git clone http://git.code.sf.net/p/tinyfiledialogs/code tinyfd

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
*/

/* not cross platform - unix zenity only */
/* contributed by Attila Dusnoki */
#ifndef _WIN32
char * tinyfd_arrayDialog(
	char const * aTitle , /* NULL or "" */
	int aNumOfColumns , /* 2 */
	char const * const * aColumns, /* {"Column 1","Column 2"} */
	int aNumOfRows, /* 2 */
	char const * const * aCells);
		/* {"Row1 Col1","Row1 Col2","Row2 Col1","Row2 Col2"} */
#endif /*_WIN32 */

/* not cross platform - UNIX and OSX only */
/* contributed by srikanth http://sourceforge.net/u/cr1vct/profile */
#ifndef _WIN32
char * tinyfd_checklistDialog(
    char const * aTitle ,
    int aNumOfOptions ,
    char const * const * aOptions);
#endif /*_WIN32 */
