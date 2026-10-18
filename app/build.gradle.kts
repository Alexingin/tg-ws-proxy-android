import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.amurcanov.tgwsproxy"
    compileSdk = 35

    defaultConfig {
        // Свой applicationId: с чужим именем пакета, но другой подписью Play Защита
        // считает APK подменённым и блокирует. Пространство имён кода (namespace) прежнее.
        applicationId = "io.github.alexingin.tgwsproxy"
        targetSdk = 35
        versionCode = 124
        // Для тестовых сборок CI добавляет суффикс: -PversionSuffix=-dev.42
        versionName = "1.2.4" + (project.findProperty("versionSuffix")?.toString() ?: "")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    flavorDimensions.add("arch")
    productFlavors {
        create("arm32") {
            dimension = "arch"
            minSdk = 21
            ndk {
                abiFilters.clear()
                abiFilters.add("armeabi-v7a")
            }
        }
        create("arm64") {
            dimension = "arch"
            minSdk = 24
            ndk {
                abiFilters.clear()
                abiFilters.add("arm64-v8a")
            }
        }
        create("universal") {
            dimension = "arch"
            minSdk = 21
            ndk {
                abiFilters.clear()
                abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a"))
            }
        }
    }

    val localProperties = Properties()
    val localPropertiesFile = rootProject.file("local.properties")
    if (localPropertiesFile.exists()) {
        localProperties.load(localPropertiesFile.inputStream())
    }

    // Источник релизного ключа: переменные окружения (GitHub Actions Secrets)
    // или local.properties (локальная сборка). Если нет ни того, ни другого —
    // release подписывается тестовым ключом ci-debug-key.p12.
    fun signingValue(env: String, prop: String): String? =
        System.getenv(env)?.takeIf { it.isNotBlank() } ?: localProperties.getProperty(prop)

    val releaseKeyPath = signingValue("RELEASE_KEYSTORE_FILE", "KEYSTORE_FILE")
    val releaseKeyFile = releaseKeyPath?.let { path ->
        if (path.startsWith("..")) file(rootDir.resolve(path.substring(3))) else file(path)
    }?.takeIf { it.exists() }

    signingConfigs {
        // Тестовый ключ форка (пароль открыт) — только для отладочных сборок.
        getByName("debug") {
            val ciKey = rootProject.file("ci-debug-key.p12")
            if (ciKey.exists()) {
                storeFile = ciKey
                storeType = "pkcs12"
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
        create("release") {
            if (releaseKeyFile != null) {
                storeFile = releaseKeyFile
                storePassword = signingValue("RELEASE_KEYSTORE_PASSWORD", "KEYSTORE_PASSWORD")
                keyAlias = signingValue("RELEASE_KEY_ALIAS", "KEY_ALIAS")
                keyPassword = signingValue("RELEASE_KEY_PASSWORD", "KEY_PASSWORD")
            }
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = if (releaseKeyFile != null) {
                println("Release signing: ${releaseKeyFile.name}")
                signingConfigs.getByName("release")
            } else {
                println("WARNING: release keystore not found, signing release with the test key")
                signingConfigs.getByName("debug")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    // composeOptions removed — AGP 9.x handles Compose compiler internally
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")

    // DataStore for persistent settings
    implementation("androidx.datastore:datastore-preferences:1.1.1")

    // JNA for easy C-shared library calls
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    debugImplementation("com.squareup.leakcanary:leakcanary-android:2.14")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.appcompat:appcompat:1.6.1")
}
