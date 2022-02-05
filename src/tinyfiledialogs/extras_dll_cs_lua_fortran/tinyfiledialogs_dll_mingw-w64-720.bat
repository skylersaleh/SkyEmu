:: cd C:\Users\frogs\yomspace2015\yomlibs\tinyfd\extras_dll_cs_lua_fortran

:: x86
\mingw-w64-720\mingw32\bin\gcc -ansi -std=c89 -pedantic -Wstrict-prototypes -m32 -Wall -c ../tinyfiledialogs.c
\mingw-w64-720\mingw32\bin\dlltool --export-all-symbols -l tinyfiledialogs32.lib tinyfiledialogs.o --dllname tinyfiledialogs32.dll
\mingw-w64-720\mingw32\bin\gcc -m32 -shared -static-libgcc tinyfiledialogs.o -o tinyfiledialogs32.dll -L\mingw-w64-720\mingw32\lib -lcomdlg32 -lole32
\mingw-w64-720\mingw32\bin\gcc -ansi -std=c89 -pedantic -Wstrict-prototypes -m32 -Wall -o hello32.exe ../hello.c tinyfiledialogs32.lib
\mingw-w64-720\mingw32\bin\gcc -ansi -std=c89 -pedantic -Wstrict-prototypes -m32 -Wall -o helloW32.exe ../hello_wchar_t.c tinyfiledialogs32.lib

\mingw-w64-720\mingw32\bin\gcc -pedantic -Wstrict-prototypes -m32 -Wall -c ../tinyfiledialogs.c
\mingw-w64-720\mingw32\bin\dlltool --export-all-symbols -l tinyfiledialogs32.lib tinyfiledialogs.o --dllname tinyfiledialogs32.dll
\mingw-w64-720\mingw32\bin\gcc -m32 -shared -static-libgcc tinyfiledialogs.o -o tinyfiledialogs32.dll -L\mingw-w64-720\mingw32\lib -lcomdlg32 -lole32
\mingw-w64-720\mingw32\bin\gcc -pedantic -Wstrict-prototypes -m32 -Wall -o hello32.exe ../hello.c tinyfiledialogs32.lib
\mingw-w64-720\mingw32\bin\gcc -pedantic -Wstrict-prototypes -m32 -Wall -o helloW32.exe ../hello_wchar_t.c tinyfiledialogs32.lib

:: x64
\mingw-w64-720\mingw64\bin\gcc -ansi -std=c89 -pedantic -Wstrict-prototypes -m64 -Wall -c ../tinyfiledialogs.c
\mingw-w64-720\mingw64\bin\dlltool --export-all-symbols -l tinyfiledialogs64.lib tinyfiledialogs.o --dllname tinyfiledialogs64.dll
\mingw-w64-720\mingw64\bin\gcc -m64 -shared -static-libgcc tinyfiledialogs.o -o tinyfiledialogs64.dll -L\mingw-w64-720\mingw64\lib -lcomdlg32 -lole32
\mingw-w64-720\mingw64\bin\gcc -ansi -std=c89 -pedantic -Wstrict-prototypes -m64 -Wall -o hello64.exe ../hello.c tinyfiledialogs64.lib
\mingw-w64-720\mingw64\bin\gcc -ansi -std=c89 -pedantic -Wstrict-prototypes -m64 -Wall -o helloW64.exe ../hello_wchar_t.c tinyfiledialogs64.lib

\mingw-w64-720\mingw64\bin\gcc -pedantic -Wstrict-prototypes -m64 -Wall -c ../tinyfiledialogs.c
\mingw-w64-720\mingw64\bin\dlltool --export-all-symbols -l tinyfiledialogs64.lib tinyfiledialogs.o --dllname tinyfiledialogs64.dll
\mingw-w64-720\mingw64\bin\gcc -m64 -shared -static-libgcc tinyfiledialogs.o -o tinyfiledialogs64.dll -L\mingw-w64-720\mingw64\lib -lcomdlg32 -lole32
\mingw-w64-720\mingw64\bin\gcc -pedantic -Wstrict-prototypes -m64 -Wall -o hello64.exe ../hello.c tinyfiledialogs64.lib
\mingw-w64-720\mingw64\bin\gcc -pedantic -Wstrict-prototypes -m64 -Wall -o helloW64.exe ../hello_wchar_t.c tinyfiledialogs64.lib

@REM \mingw-w64\mingw64\bin\gcc -std=c89 -o hello.exe tinyfiledialogs.c hello.c -LC:\mingw-w64\mingw64\lib -lcomdlg32 -lole32
