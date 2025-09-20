#-------------------------------------------------------------------------------
#   SokolShader.py
#
#   Fips code-generator script for invoking sokol-shdc during the build.
#
#   Use the cmake macro 'sokol_shader([glsl-file] [shader-dialects])' inside a
#   fips target (fips_begin_* / fips_end_*) to hook the code-generation
#   build job into the build process.
#-------------------------------------------------------------------------------

Version = 4

import os, platform, subprocess
import genutil as util
from mod import log

#-------------------------------------------------------------------------------
def find_shdc():
    shdc_path = os.path.dirname(os.path.abspath(__file__))
    shdc_path += '/../../bin/'
    if platform.system() == 'Windows':
        shdc_path += 'win32/'
    elif platform.system() == 'Darwin':
        if platform.machine() == 'arm64':
            shdc_path += 'osx_arm64/'
        else:
            shdc_path += 'osx/'
    elif platform.system() == 'Linux':
        if os.uname()[1] == 'raspberrypi':
            shdc_path += 'raspi/'
        else:
            shdc_path += 'linux/'
    else:
        log.error('Unknown host system {}'.format(platform.system()))
    return shdc_path + 'sokol-shdc'

#-------------------------------------------------------------------------------
def generate(input, out_src, out_hdr, args):
    errfmt = 'msvc' if args['compiler']=='MSVC' else 'gcc'
    if util.isDirty(Version, [input], [out_hdr]):
        print('## sokol-shdc: {} {} {}'.format(input, out_hdr, str(args)))
        cmd = [find_shdc(), 
                '--input', input,
                '--output', out_hdr,
                '--slang', args['slang'],
                '--genver', str(Version),
                '--errfmt', errfmt,
                '--format', 'sokol',
                '--bytecode']
        if 'defines' in args:
            cmd.extend(['--defines', args['defines']])
        if 'module' in args:
            cmd.extend(['--module', args['module']])
        if 'reflection' in args:
            if args['reflection']:
                cmd.extend(['--reflection'])
        res = subprocess.call(cmd)
        if res != 0:
            log.error('sokol-shdc returned with error code {}'.format(res))
