
import os
import shutil
from PIL import Image,ImageDraw

def apply_overlay(orig_path, overlay_path, output_path):
  orig= Image.open(orig_path)
  overlay= Image.open(overlay_path)
  orig = Image.alpha_composite(orig,overlay)
  orig.save(output_path);       
def image_dims(path):
  return Image.open(path).size;

def combine_horz_images(images,overlay_path, output_path,width = 10):
  final_image = Image.open(images[0][0]);
  for im in images[1:]:
    append_im = Image.open(im[0])
    x_off = int(im[1]);
    append_im=append_im.crop((x_off,0,append_im.size[0],append_im.size[1]));
    final_image.paste(append_im,(x_off,0));
    draw = ImageDraw.Draw(final_image)
    draw.line([(x_off,0), (x_off,final_image.size[1])], fill=(20,20,20), width=width)
  
  overlay= Image.open(overlay_path)
  final_image = Image.alpha_composite(final_image,overlay)
  final_image.save(output_path);            

 
def combine_vert_images(images,overlay_path, output_path,width = 10):
  final_image = Image.open(images[0][0]);
  for im in images[1:]:
    append_im = Image.open(im[0])
    y_off = int(im[1]);
    append_im=append_im.crop((0,y_off,append_im.size[0],append_im.size[1]));
    final_image.paste(append_im,(0,y_off));
    draw = ImageDraw.Draw(final_image)
    draw.line([(0,y_off), (final_image.size[0],y_off)], fill=(20,20,20), width=width)
  
  overlay= Image.open(overlay_path)
  final_image = Image.alpha_composite(final_image,overlay)
  final_image.save(output_path);            

      
in_dir = "images/"
out_dir = "final/"
if os.path.exists(out_dir):
  shutil.rmtree(out_dir)
os.makedirs(out_dir)
for p in ["phone","tablet-7in","tablet-10in"]:
  os.makedirs(out_dir+p)
  p1 = in_dir + p+"/"
  p2 = in_dir + p+"/"
  out_p = out_dir+p+"/"
  easy_to_use_overlay = "overlays/easy-to-use-land.png"
  if p == "phone":
    p1 = in_dir + p + "-portrait/"
    p2 = in_dir + p + "-landscape/"
    easy_to_use_overlay = "overlays/easy-to-use.png"
  apply_overlay(p1+"select.png",easy_to_use_overlay,out_p+"1.png")
  select_width = image_dims(p1+"select-2.png")[1]
  #combine_vert_images(
  #  [
  #    [p1+"select-2.png", 0.0],
  #    [p1+"select-0.png", select_width/3],
  #    [p1+"select-1.png", select_width*2/3]
  #  ],easy_to_use_overlay,out_p+"1-2.png",10) 
  combine_horz_images(
    [
      [p2+"shader-0.png", 0.0],
      [p2+"shader-1.png", 402.0+1100/4.0*1.0],
      [p2+"shader-2.png", 402.0+1100/4.0*2.0],
      [p2+"shader-3.png", 402.0+1100/4.0*3.0]
    ],"overlays/shaders.png",out_p+"2.png")
  apply_overlay(p2+"features.png","overlays/features.png",out_p+"3.png")
  apply_overlay(p2+"controller.png","overlays/controller.png",out_p+"/4.png")
  apply_overlay(p2+"nds.png","overlays/nds.png",out_p+"5.png")
