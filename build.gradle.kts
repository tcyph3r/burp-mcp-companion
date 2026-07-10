plugins {
    kotlin("jvm") version "2.3.21"
    kotlin("plugin.serialization") version "2.3.21"
    java
}

repositories {
    mavenCentral()
}

val ktorVersion = "3.0.3"
val mcpSdkVersion = "0.13.0"
val serializationVersion = "1.7.3"

dependencies {
    // Burp Suite Montoya API (provided by Burp at runtime)
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")

    // Kotlin stdlib
    implementation("org.jetbrains.kotlin:kotlin-stdlib")

    // MCP Kotlin SDK
    implementation("io.modelcontextprotocol:kotlin-sdk:$mcpSdkVersion")

    // Ktor Server (SSE transport for MCP)
    implementation("io.ktor:ktor-server-core:$ktorVersion")
    implementation("io.ktor:ktor-server-netty:$ktorVersion")
    implementation("io.ktor:ktor-server-sse:$ktorVersion")
    implementation("io.ktor:ktor-server-cors:$ktorVersion")

    // kotlinx.serialization for JSON
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:$serializationVersion")

    // SLF4J no-op to suppress Ktor/Netty logging noise inside Burp
    implementation("org.slf4j:slf4j-nop:2.0.16")
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
        vendor.set(JvmVendorSpec.ADOPTIUM)
    }
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.named<Jar>("jar") {
    // Fat JAR: bundle all runtime dependencies
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })

    // Exclude module-info and signature files that cause conflicts
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    exclude("META-INF/MANIFEST.MF")
    exclude("META-INF/versions/*/module-info.class")
}