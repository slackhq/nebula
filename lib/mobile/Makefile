111MODULE = on
export GO111MODULE

lib-android:
	gomobile bind -v --target=android
	rm mobileNebula-sources.jar

lib-ios:
	gomobile bind -v --target=ios


.DEFAULT_GOAL := all

all: lib-android lib-ios
