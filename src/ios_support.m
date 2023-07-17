#include "ios_support.h"
#include "sokol_app.h"
#include <stdio.h>
#import <UIKit/UIKit.h>

@interface SelectorDelegate : UIViewController

@end
@interface SelectorDelegate () <UIDocumentPickerDelegate>

@end

@implementation SelectorDelegate

extern void se_load_rom(const char *filename);

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentAtURL:(NSURL *)url {
    if (controller.documentPickerMode == UIDocumentPickerModeImport) {
        /*NSString *alertMessage = [NSString stringWithFormat:@"Successfully imported %@", [url lastPathComponent]];
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *alertController = [UIAlertController
                                                  alertControllerWithTitle:@"Import"
                                                  message:alertMessage
                                                  preferredStyle:UIAlertControllerStyleAlert];
            [alertController addAction:[UIAlertAction actionWithTitle:@"Ok" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alertController animated:YES completion:nil];
        });*/
      NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
      NSString *documentsPath = [paths objectAtIndex:0];
      documentsPath = [documentsPath stringByAppendingString:@"/"];
      documentsPath = [documentsPath stringByAppendingString:[url lastPathComponent]];
      NSURL * new_url = [NSURL fileURLWithPath:documentsPath];
      
      NSLog(@"Copy from: %@ to: %@ (%@)\n",[url absoluteURL],[new_url absoluteURL],documentsPath);

      NSError*error = Nil;
      [[NSFileManager defaultManager] removeItemAtURL:new_url error:&error];
      error = Nil;
      [[NSFileManager defaultManager] copyItemAtURL:url toURL:new_url error:&error];
      if(error){
        NSLog(@"Error:%@\n",error);
      }else{
        documentsPath= [@"./" stringByAppendingString:[url lastPathComponent]];
        se_load_rom([documentsPath cStringUsingEncoding:NSUTF8StringEncoding]);
      }
    }
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    NSLog(@"Cancelled");
}

@end

void se_ios_set_documents_working_directory(){
  NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
  NSString *documentsPath = [paths objectAtIndex:0];
  documentsPath = [documentsPath stringByAppendingString:@"/"];
  chdir([documentsPath cStringUsingEncoding:NSUTF8StringEncoding]);
}
char* se_ios_open_file_picker( int num_extensions, const char ** extensions){
  printf("Open iOS file picker");
    UIDocumentPickerViewController *documentPicker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.item"]
        inMode:UIDocumentPickerModeImport];

    UIViewController * view = (UIViewController*)sapp_ios_get_view_ctrl();
    documentPicker.modalPresentationStyle = UIModalPresentationFormSheet;
  documentPicker.delegate = [SelectorDelegate alloc];
    [view presentViewController:documentPicker animated:YES completion:nil];
    return NULL;
}
void se_ios_get_safe_ui_padding(float *top, float* bottom,float* left, float *right){
  if(top)*top=0;
  if(bottom)*bottom=0;
  if(left)*left=0;
  if(right)*right=0;
  if (@available(iOS 11.0, *)) {
    UIWindow *window = UIApplication.sharedApplication.windows.firstObject;
    if(top)*top = window.safeAreaInsets.top;
    if(bottom)*bottom = window.safeAreaInsets.bottom;
    if(left)*left = window.safeAreaInsets.left;
    if(right)*right = window.safeAreaInsets.right;
  }
}
