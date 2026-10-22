#!/bin/sh
)):
if [ -x "gradle/wrapper/gradle-wrapper.jar" ]; then
	exec "gradle/wrapper/gradle-wrapper.jar" "$@"
else
	echo "Gradle Wrapper not found. Please ensure gradle/wrapper/gradle-wrapper.jar exists."
	exit 1
fi
