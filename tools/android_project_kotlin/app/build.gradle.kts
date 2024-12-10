plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("kotlin-parcelize")
    kotlin("plugin.serialization") version "2.1.0"
    id("androidx.navigation.safeargs.kotlin")
}

android {
    signingConfigs {
        create("release") {
            storePassword = "skyemu-super-secure-password"
            keyAlias = "skyemu-open-code-certificate"
            keyPassword = "skyemu-super-secure-password"
            storeFile = file("../skyemu-open-signing-store")
        }
    }
    namespace = "com.sky.SkyEmu"
    compileSdk = 34
    ndkVersion = "22.1.7171670"

    defaultConfig {
        signingConfig = signingConfigs.getByName("release")
        applicationId = "com.sky.SkyEmu"
        minSdk = 28
        targetSdk = 34
        versionCode = 32
        versionName = "v3.2"
        setProperty("archivesBaseName", "$applicationId-v$versionCode")
        externalNativeBuild {
            cmake {
                arguments += listOf(
                    "-DANDROID_STL=c++_static",
                    "-DANDROID=1",
                    "-DNDK_DEBUG=0",
                    "-DCMAKE_BUILD_TYPE=RELWITHDEBINFO",
                    "-DANDROID_ARM_NEON=TRUE"
                )
                targets += "SkyEmu"
            }
        }
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android.txt"),
                "proguard-rules.pro"
            )
        }
    }

    externalNativeBuild {
        cmake {
            version = "3.18.1"
            path = file("../../../CMakeLists.txt")
        }
    }
}

dependencies {
    implementation(fileTree("libs") { include("*.jar") })
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7")
    implementation("androidx.navigation:navigation-fragment-ktx:2.8.4")
    implementation("androidx.navigation:navigation-ui-ktx:2.8.4")
    implementation("androidx.preference:preference-ktx:1.2.1")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.swiperefreshlayout:swiperefreshlayout:1.1.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.browser:browser:1.5.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
}
