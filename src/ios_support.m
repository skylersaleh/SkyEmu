#include "ios_support.h"
#include "sokol_app.h"
#include <stdio.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <SafariServices/SafariServices.h> // added for secure browser support


@interface SelectorDelegate : NSObject <UIDocumentPickerDelegate>

@end

@implementation SelectorDelegate

extern void se_file_browser_accept(const char *filename);

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentAtURL:(NSURL *)url {
    if (controller.documentPickerMode == UIDocumentPickerModeImport||controller.documentPickerMode== UIDocumentPickerModeOpen) {
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
        se_file_browser_accept([documentsPath cStringUsingEncoding:NSUTF8StringEncoding]);
      }
    }
}
- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)array {
  for(NSURL* url in array){
    [self documentPicker:controller didPickDocumentAtURL:url];
  }
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {
    NSLog(@"Cancelled");
}

@end
#import <UIKit/UIViewController.h>
#import <objc/runtime.h>

@implementation UIViewController (Swizzling)

+ (void)load
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class class = [self class];
        SEL originalSelector = @selector(preferredScreenEdgesDeferringSystemGestures);
        SEL swizzledSelector = @selector(preferredScreenEdgesDeferringSystemGesturesSwizzled);
        Method originalMethod = class_getInstanceMethod(class, originalSelector);
        Method swizzledMethod = class_getInstanceMethod(class, swizzledSelector);
        
        const BOOL didAdd = class_addMethod(class, originalSelector, method_getImplementation(swizzledMethod), method_getTypeEncoding(swizzledMethod));
        if (didAdd)
          class_replaceMethod(class, swizzledSelector, method_getImplementation(originalMethod), method_getTypeEncoding(originalMethod));
        else
          method_exchangeImplementations(originalMethod, swizzledMethod);
    });
}

- (UIRectEdge)preferredScreenEdgesDeferringSystemGestures
{
    return UIRectEdgeAll;
}

- (UIRectEdge)preferredScreenEdgesDeferringSystemGesturesSwizzled
{
    return UIRectEdgeAll;
}


@end

void se_ios_set_documents_working_directory(){
  NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
  NSString *documentsPath = [paths objectAtIndex:0];
  documentsPath = [documentsPath stringByAppendingString:@"/"];
  chdir([documentsPath cStringUsingEncoding:NSUTF8StringEncoding]);
}
static SelectorDelegate * sel_del = nil;
void se_ios_open_file_picker( int num_extensions, const char ** extensions){
  if(sel_del ==nil)sel_del =[[SelectorDelegate alloc]init];
  printf("Open iOS file picker");
    UIDocumentPickerViewController *documentPicker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.item"]
        inMode:UIDocumentPickerModeImport];

    UIViewController * view = (UIViewController*)sapp_ios_get_view_ctrl();
    documentPicker.modalPresentationStyle = UIModalPresentationFormSheet;
  documentPicker.delegate = sel_del;
    [view presentViewController:documentPicker animated:YES completion:nil];
}
void se_ios_get_safe_ui_padding(float *top, float* bottom,float* left, float *right){
  if(top)*top=0;
  if(bottom)*bottom=0;
  if(left)*left=0;
  if(right)*right=0;
  if (@available(iOS 11.0, *)) {
    UIWindow *window = [UIApplication.sharedApplication.windows lastObject];
    if(top)*top = window.safeAreaInsets.top;
    if(bottom)*bottom = window.safeAreaInsets.bottom;
    if(left)*left = window.safeAreaInsets.left;
    if(right)*right = window.safeAreaInsets.right;
  }
}
UIViewController* get_web_view_controller(){
  static UIViewController* wvc = nil;
  if(wvc==nil)wvc = [[UIViewController alloc] init];
  return wvc;
}

// add a static to hold the presented secure browser so se_ios_close_modal can dismiss it
static UIViewController *g_presented_secure_vc = nil;

void se_ios_open_modal(const char * url){
  //Make a URL here so that the block captures a copy of the variable instead of a copy of the pointer
  NSURL* nsurl = [NSURL URLWithString:[NSString stringWithUTF8String:url]];
  
  [[NSOperationQueue mainQueue] addOperationWithBlock:^ {
       UIViewController *rootViewController = (UIViewController *)sapp_ios_get_view_ctrl();
       
       // Use SFSafariViewController for remote (http/https) URLs to comply with secure browser policy.
       // Use an embedded WKWebView only for local/file content.
       NSString *scheme = [[nsurl scheme] lowercaseString] ?: @"";
       if ([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"]) {
           if (@available(iOS 9.0, *)) {
               SFSafariViewController *safariVC = [[SFSafariViewController alloc] initWithURL:nsurl];
               safariVC.modalPresentationStyle = UIModalPresentationFullScreen;
               g_presented_secure_vc = safariVC;
               [rootViewController presentViewController:safariVC animated:YES completion:nil];
           } else {
               // Fallback: open the URL in the system browser for older iOS versions.
               if ([[UIApplication sharedApplication] respondsToSelector:@selector(openURL:options:completionHandler:)]) {
                   [[UIApplication sharedApplication] openURL:nsurl options:@{} completionHandler:nil];
               } else {
                   [[UIApplication sharedApplication] openURL:nsurl];
               }
           }
       } else {
           // Treat non-http(s) as local/in-app content: present with a WKWebView embedded controller.
           // This preserves the previous embedded view behavior for file:// or app-local content.
           WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];
           WKWebView *webView = [[WKWebView alloc] initWithFrame:rootViewController.view.bounds configuration:configuration];
           webView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;

           UIViewController *webViewController = get_web_view_controller();
           webViewController.view.backgroundColor = [UIColor whiteColor];
           // remove any previous subviews to avoid duplicates
           for (UIView *v in [webViewController.view subviews]) { [v removeFromSuperview]; }
           [webViewController.view addSubview:webView];

           NSURLRequest *request = [NSURLRequest requestWithURL:nsurl
                                                    cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                timeoutInterval:30.0];
           [webView loadRequest:request];

           g_presented_secure_vc = webViewController;
           [rootViewController presentViewController:webViewController animated:YES completion:nil];
       }
   }];
}
void se_ios_close_modal(){
  [[NSOperationQueue mainQueue] addOperationWithBlock:^ {
    if (g_presented_secure_vc) {
      [g_presented_secure_vc dismissViewControllerAnimated:YES completion:nil];
      g_presented_secure_vc = nil;
    } else {
      // best-effort fallback
      [get_web_view_controller() dismissViewControllerAnimated:YES completion:nil];
    }
   }];
}
