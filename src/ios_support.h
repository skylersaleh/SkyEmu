#ifndef IOS_SUPPORT_H
#define IOS_SUPPORT_H 1

void se_ios_open_file_picker( int num_extensions, const char ** extensions);
void se_ios_get_safe_ui_padding(float *top, float* bottom,float* left, float *right);
void se_ios_set_documents_working_directory();
#endif
