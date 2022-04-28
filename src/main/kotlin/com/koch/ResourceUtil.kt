package com.koch

import java.net.URL

class ResourceUtil {

    companion object {
        @JvmStatic
        fun loadResource(resource: String): URL {
            return try {
                this::class.java.getResource(resource)
            } catch (e: Exception) {
                throw Exception("There was an error when loading the ressource $resource: $e")
            }
        }
    }

}