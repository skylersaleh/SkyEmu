if [ ! -d "android_sdk" ] ; then
    mkdir -p android_sdk && cd android_sdk
    sdk_file="sdk-tools-linux-3859397.zip"
    wget --no-verbose https://dl.google.com/android/repository/$sdk_file
    unzip -q $sdk_file
    cd tools/bin
    yes | ./sdkmanager "platforms;android-28" 
    yes | ./sdkmanager "build-tools;29.0.3" 
    yes | ./sdkmanager "platform-tools" 
    yes | ./sdkmanager "ndk-bundle" 
    cd ../../..
fi
if [ ! -d "cmake_build" ] ; then
    rm -rf cmake_build
fi
mkdir cmake_build
cd cmake_build
cmake ../../ -GNinja -DANDROID_ABI=armeabi-v7a -DANDROID_PLATFORM=android-28 -DCMAKE_TOOLCHAIN_FILE="../android_sdk/ndk-bundle/build/cmake/android.toolchain.cmake" -DCMAKE_BUILD_TYPE=Release 
cmake --build .
cd ..