import pywinctl as gw
import urllib.request
import shutil                        
import os
import time

dot_to_pixel_factor = 2
border_top = 28
border_bottom = 10
border_sides =1; 
hcs_url = "http://localhost:8080/"
program_name = "SkyEmu"

out_dir = "images/"
win = gw.getWindowsWithTitle(program_name)[0];

win.alwaysOnTop()
resolutions =[
  [1920, 1080, 480, "phone-landscape"],
  [1080, 1920, 480, "phone-portrait"],
  [1920, 1080, 360, "tablet-7in"],
  [1920, 1080, 240,  "tablet-10in"],
]

if os.path.exists(out_dir):
  shutil.rmtree(out_dir)
os.makedirs(out_dir)
win_x=0
win_y=0
win_width=0
win_height=0
def resize_win(w, h):
  print("resize");
  win.moveTo(100,40);
  win.resizeTo(w/dot_to_pixel_factor+border_sides*2,h/dot_to_pixel_factor+border_bottom+border_top);
  global win_x, win_y, win_width, win_height
  win_x, win_y, win_width, win_height = win.left, win.top, win.width, win.height
  
from PIL import ImageGrab

def capture_active_window(filename):
    print("capture")
    time.sleep(0.1);
    global win_x, win_y, win_width, win_height
    x, y, width, height = win_x, win_y, win_width, win_height
    x+= border_sides
    width -=border_sides*2
    y+=border_top
    height-=border_top+border_bottom
    x*= dot_to_pixel_factor
    y*= dot_to_pixel_factor
    width*= dot_to_pixel_factor
    height*= dot_to_pixel_factor
    screenshot = ImageGrab.grab(bbox=(x, y, x + width, y + height))
    screenshot.save(filename);

def send_hcs_cmd(cmd):
  return urllib.request.urlopen(hcs_url+cmd).read()

                 
send_hcs_cmd(f"setting?debug_tools=0&fake_paths=1")
for res in resolutions:
  resize_win(res[0],res[1]);
  touch_scale = res[2]/500.; 
  path = out_dir + res[3]+"/";
  os.makedirs(path);
  
  send_hcs_cmd(f"setting?theme=0")
  send_hcs_cmd(f"setting?menu_bar=1&shader=3")
  send_hcs_cmd(f"setting?ui_type=ANDROID&touch_controls_scale={touch_scale}")
  send_hcs_cmd("load_rom?path=/Users/skylersaleh/Documents/roms/gba/varooom-3d.gba")
  send_hcs_cmd(f"setting?menu=1&dpi={res[2]}&load_slot=2&edit_cheat_index=3")
  capture_active_window(path+f"features.png");
  send_hcs_cmd(f"setting?menu=0&dpi={res[2]}&load_slot=0&edit_cheat_index=3")
  capture_active_window(path+f"controller.png");
  send_hcs_cmd(f"step");
  capture_active_window(path+f"select.png");
  send_hcs_cmd(f"setting?theme=0")
  capture_active_window(path+f"select-0.png");
  send_hcs_cmd(f"setting?theme=1")
  capture_active_window(path+f"select-1.png");
  send_hcs_cmd(f"setting?theme=2")
  capture_active_window(path+f"select-2.png");
  send_hcs_cmd(f"setting?theme=0")
  
  send_hcs_cmd("load_rom?path=/Users/skylersaleh/Documents/roms/nds/26105-DScraft_NitroFS_310811/DScraft.nds")
  send_hcs_cmd(f"setting?menu=0&dpi={res[2]}&load_slot=0")
  capture_active_window(path+f"nds.png");
 
  send_hcs_cmd("load_rom?path=/Users/skylersaleh/Documents/roms/gbc/Deadeus/Deadeus.gb")

  send_hcs_cmd(f"setting?menu_bar=0")
  send_hcs_cmd(f"setting?shader=3&load_slot=2")
  capture_active_window(path+f"shader-1.png");
  send_hcs_cmd(f"setting?shader=0&load_slot=3")
  capture_active_window(path+f"shader-0.png");
  send_hcs_cmd(f"setting?shader=3&load_slot=3")
  capture_active_window(path+f"shader-2.png");
  send_hcs_cmd(f"setting?shader=4&load_slot=3")
  capture_active_window(path+f"shader-3.png");
  send_hcs_cmd(f"setting?menu_bar=1")
