!  _________
! /         \ tinyfiledialogs v3.8.3 [Nov 3, 2020] zlib licence
! |tiny file| 
! | dialogs | Copyright (c) 2014 - 2020 Guillaume Vareille http://ysengrin.com
! \____  ___/ http://tinyfiledialogs.sourceforge.net
!      \|     git clone http://git.code.sf.net/p/tinyfiledialogs/code tinyfd

! - License -
! This software is provided 'as-is', without any express or implied
! warranty.  In no event will the authors be held liable for any damages
! arising from the use of this software.
! Permission is granted to anyone to use this software for any purpose,
! including commercial applications, and to alter it and redistribute it
! freely, subject to the following restrictions:
! 1. The origin of this software must not be misrepresented; you must not
! claim that you wrote the original software.  If you use this software
! in a product, an acknowledgment in the product documentation would be
! appreciated but is not required.
! 2. Altered source versions must be plainly marked as such, and must not be
! misrepresented as being the original software.
! 3. This notice may not be removed or altered from any source distribution.

! this fortran code for tinyfiledialogs was contributed by Bo Sundman
! https://github.com/sundmanbo/opencalphad

module ftinyopen
  use iso_c_binding
  implicit none

! A C function that returns a string need a pointer to the array of single char 
  type (c_ptr) :: C_String_ptr
! This is the Fortran equivalent to a string of single char
  character (len=1, kind=c_char), dimension(:), pointer :: filchar => null()

!\begin{verbatim}
! Interface to a C routine which opens a window for browsing a file to open
  interface
     function tinyopen(typ) bind(c, name="tinyopen")
       use iso_c_binding
       implicit none
       integer(c_int), value :: typ
       type (C_Ptr) :: tinyopen
     end function tinyopen
  end interface
!\end{verbatim}

contains

!\begin{verbatim}
  subroutine getfilename(typ,filename)
! Fortran routine to call a C routine to browse for a file name
! typ if default extension:
! 1=TDB, 2=UNF, 3=OCM, 4=OCD
    character (len=256) :: filename
    integer typ
!\end{verbatim}
    integer jj
! specify a name of a TDB file (typ=1)
    C_String_ptr = tinyopen(typ)
! convert C pointer to Fortran pointer
    call c_f_pointer(C_String_ptr,filchar,[256])
    filename=' '
    if(associated(filchar)) then
! convert the array of single characters to a Fortran character
       jj=1
       do while(filchar(jj).ne.c_null_char)
          filename(jj:jj)=filchar(jj)
          jj=jj+1
       enddo
    endif
!    write(*,*)'In getfilename: ',trim(filename)
1000 continue
    return
  end subroutine getfilename
end module ftinyopen


