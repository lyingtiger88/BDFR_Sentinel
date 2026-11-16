package com.bdfr.sentinel

/**
 * JNI facade. The shared Rust library is loaded only when the Android package
 * includes the ABI-matched sentinel_android_ffi shared object.
 */
class NativeScanner {
    companion object {
        val isAvailable: Boolean = try {
            System.loadLibrary("sentinel_android_ffi")
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    external fun scanBytes(data: ByteArray, label: String, appDataDir: String): String
}
