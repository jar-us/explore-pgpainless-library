plugins {
    kotlin("jvm") version "1.9.23"
}

group = "jar.us"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.pgpainless:pgpainless-core:1.6.6")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}