plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.personalvpn.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.personalvpn.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    buildFeatures {
        viewBinding = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(fileTree("libs") { include("*.aar") })
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-ktx:1.9.2")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
