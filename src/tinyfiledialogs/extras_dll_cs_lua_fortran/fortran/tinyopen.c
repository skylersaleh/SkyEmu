/*_________
 /         \ tinyfiledialogs v3.8.3 [Nov 3, 2020] zlib licence
 |tiny file| 
 | dialogs | Copyright (c) 2014 - 2020 Guillaume Vareille http://ysengrin.com
 \____  ___/ http://tinyfiledialogs.sourceforge.net
      \|     git clone http://git.code.sf.net/p/tinyfiledialogs/code tinyfd

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

 this fortran code for tinyfiledialogs was contributed by Bo Sundman
 https://github.com/sundmanbo/opencalphad     */


/* dummy C routine that returns a legal filename */

#include <stdio.h>
#include <string.h>
#include "tinyfiledialogs.h"

char const * tinyopen(int const typ)
{
  char const * lFilterPatterns1[1] = {"*.TDB"};
  char const * lFilterPatterns2[1] = {"*.UNF"};
  char const * lFilterPatterns3[1] = {"*.OCM"};
  char const * lFilterPatterns4[1] = {"*.OCD"};
  char const * lFilterPatterns5[1] = {"*.PLT"};
  char const * p2;
  //printf("start of tinydummy \n");
  //printf("input value of typ: %i \n",typ);
  //printf("now copy the string \n");
  //strcpy(filename,"C:\\User\\Bosse\\Document\\Software\\openfile\\test.TDB");
  if(typ<0)
    {
      //lTheOpenFileName = tinyfd_saveFileDialog(
      p2 = tinyfd_saveFileDialog(
					       "Output file name",
					       "",
					       0,
					       NULL,
					       NULL);
    }
  else if(typ==1)
    {
      //lTheOpenFileName = tinyfd_openFileDialog(
      p2 = tinyfd_openFileDialog(
					       "Input file name",
					       "",
					       1,
					       lFilterPatterns1,
					       NULL,
					       0);
    }
  else if(typ==2)
    {
      //lTheOpenFileName = tinyfd_openFileDialog(
      p2 = tinyfd_openFileDialog(
					       "Input file name",
					       "",
					       1,
					       lFilterPatterns2,
					       NULL,
					       0);
      //p2="C:\\User\\Bosse\\Document\\Software\\openfile\\test.UNF";
    }
  else if(typ==3)
    {
      //lTheOpenFileName = tinyfd_openFileDialog(
      p2 = tinyfd_openFileDialog(
					       "Input file name",
					       "",
					       1,
					       lFilterPatterns3,
					       NULL,
					       0);
      //p2="C:\\User\\Bosse\\Document\\Software\\openfile\\test.UNF";
    }
  else if(typ==4)
    {
      //lTheOpenFileName = tinyfd_openFileDialog(
      p2 = tinyfd_openFileDialog(
					       "Input file name",
					       "",
					       1,
					       lFilterPatterns3,
					       NULL,
					       0);
      //p2="C:\\User\\Bosse\\Document\\Software\\openfile\\test.UNF";
    }
  else
    {
      //no default extension
      p2 = tinyfd_openFileDialog(
					       "Input file name",
					       "",
					       0,
					       NULL,
					       NULL,
					       0);
      //p2="C:\\User\\Bosse\\Document\\Software\\openfile\\test.DAT";
    }
  //if (! lTheOpenFileName)
  if (! p2)
    {
      tinyfd_messageBox(
			"Error",
			"Open file name is NULL",
			"ok",
			"error",
			1);
      return NULL ;
    }
  //printf("return name: %s \n",p2);
  //printf("end of tinydummy \n");
  //return lTheOpenFileName;
  return p2;
}
