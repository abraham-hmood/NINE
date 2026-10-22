@echo off
set LOCAL_gradle_distribution=gradle
set GRADLE_OPTS=-Dorg.gradle.daemon=true

if "%OS%"=="Windows_NT" (
    set GRADLE_JVM_ARGS=-Xmx2048m -XX:MaxMetaspaceSize=512m
)

if exist "gradle\wrapper\gradle-wrapper.jar" (
    java %GRADLE_JVM_ARGS% -cp "gradle\wrapper\gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain %*
) else (
    echo Gradle Wrapper not found. Please ensure gradle\wrapper\gradle-wrapper.jar exists.
    exit /b 1
)
