TARGET			= wtfis
BUILD_CONFIG 	= Release

CLANG 			= clang -isysroot "$(shell xcrun --show-sdk-path --sdk iphoneos)"
ARCH 			= -arch arm64
FRAMEWORKS		= -framework IOKit -framework Foundation -framework UIKit
C_FLAGS 		= -I./$(TARGET)/ -I./$(TARGET)/include
UNTETHER_FLAGS	= -DUNTETHER -mios-version-min=8.0

.PHONY: all clean untether ipa

all: clean untether ipa

ipa:
	xcodebuild clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO PRODUCT_BUNDLE_IDENTIFIER="com.therealclarity.wtfis" -sdk iphoneos -configuration $(BUILD_CONFIG)
	ln -sf build/$(BUILD_CONFIG)-iphoneos Payload
	rm -rf Payload/wtfis.app.dSYM
	xattr -cr Payload/*
	strip Payload/wtfis.app/wtfis
	zip -r9 $(TARGET).ipa Payload/$(TARGET).app

clean:
	sudo rm -rf build Payload $(TARGET).ipa **/*.deb
	sudo rm -rf untether/untether untether/untether.tar untether/wtfis untether/package
	
untether:
	$(CLANG) $(UNTETHER_FLAGS) $(ARCH) $(FRAMEWORKS) $(C_FLAGS) ./untether/main.m  ./$(TARGET)/jailbreak.m ./$(TARGET)/kernel_memory.c \
		./$(TARGET)/offsets.m ./$(TARGET)/patchfinder64.c ./$(TARGET)/exploit_utilities.c ./$(TARGET)/exploit.c -o untether/untether
	strip untether/untether
	ldid -Hsha1 -Suntether/ent.xml untether/untether
	cd untether && sudo ./package.sh app
