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

program test3
  use iso_c_binding
  use ftinyopen
  implicit none

! variables used in Fortran
  character (len=256) :: filename
  integer typ,jj

! ------------------------------------
! specify a name of a TDB file (typ=1)
  typ=1
  call getfilename(typ,filename)
!
  write(*,*)'File name is: ',trim(filename)
! ------------------------------------
! specify a name of an unformatted file (typ=2)
  typ=2
  call getfilename(typ,filename)
  write(*,*)'File name is: ',trim(filename)
  write(*,90)
90 format(/'All well that ends well'/)
end program test3

