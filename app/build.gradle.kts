plugins {
    id("com.android.application")
}

dependencies {
    implementation("org.nanohttpd:nanohttpd:2.3.1")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("junit:junit:4.13.2")
}

val releaseSigningRequested = gradle.startParameter.taskNames.any { taskName ->
    taskName.substringAfterLast(':').contains("release", ignoreCase = true)
}

fun requiredSigningEnvironment(name: String): String =
    providers.environmentVariable(name).orNull?.takeIf { it.isNotBlank() }
        ?: throw GradleException("Missing required Android signing environment variable: $name")

android {
    namespace = "com.passwordvault.local"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.passwordvault.local"
        minSdk = 28
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    val releaseSigningConfig = if (releaseSigningRequested) {
        signingConfigs.create("release") {
            val keystore = file(requiredSigningEnvironment("ANDROID_KEYSTORE_PATH"))
            if (!keystore.isFile) {
                throw GradleException("Android signing keystore file does not exist")
            }
            storeFile = keystore
            storePassword = requiredSigningEnvironment("ANDROID_KEYSTORE_PASSWORD")
            keyAlias = requiredSigningEnvironment("ANDROID_KEY_ALIAS")
            keyPassword = requiredSigningEnvironment("ANDROID_KEY_PASSWORD")
        }
    } else {
        null
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            releaseSigningConfig?.let { signingConfig = it }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    testOptions {
        managedDevices {
            localDevices {
                create("pixel2Api35") {
                    device = "Pixel 2"
                    apiLevel = 35
                    systemImageSource = "aosp"
                }
            }
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
    }
}
