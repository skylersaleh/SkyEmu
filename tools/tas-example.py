import urllib.request
import shutil                        
import os                              

# This is a simple example of using the HCS to implement TAS functionality. 
# It would be nice to make a more fleshed out example in the future. 

hcs_url = "http://localhost:8080/"

out_dir = "images/"

if os.path.exists(out_dir):
  shutil.rmtree(out_dir)
os.makedirs(out_dir)

def send_hcs_cmd(cmd):
  return urllib.request.urlopen(hcs_url+cmd).read()

                 
send_hcs_cmd("load_rom?path=/Users/skylersaleh/Documents/roms/gba/varooom-3d.gba&pause=1")
send_hcs_cmd("step?frames=1000")
for i in range(0,10):
  send_hcs_cmd(f"input?A={i%2}")
  send_hcs_cmd(f"save?path=/Users/skylersaleh/Desktop/save-a-presses-1-{i}.png")
  send_hcs_cmd("step?frames=30")
send_hcs_cmd("step?frames=1000")
send_hcs_cmd(f"save?path=/Users/skylersaleh/Desktop/save-before.png")
for i in range(0,10):
  send_hcs_cmd(f"input?A={i%2}")
  send_hcs_cmd(f"save?path=/Users/skylersaleh/Desktop/save-a-presses-2-{i}.png")
  send_hcs_cmd("step?frames=100")

send_hcs_cmd("save?path=/Users/skylersaleh/Desktop/save-after.png")

